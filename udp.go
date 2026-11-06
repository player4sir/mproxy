package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// ---------- UDP 缓冲池与会话管理 ----------

var udpBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 65535)
		return &b
	},
}

type UDPSession struct {
	clientAddr string
	outConn    *net.UDPConn
	lastActive atomic.Int64 // unix timestamp in seconds
	cancel     context.CancelFunc
}

// UDPResponseHandler 将出站目标回包重新组装为特定协议格式（如 SOCKS5 / Trojan / Shadowsocks）并送回客户端
type UDPResponseHandler func(targetHost string, targetPort int, payload []byte) error

type UDPManager struct {
	mu         sync.RWMutex
	sessions   map[string]*UDPSession
	timeout    time.Duration
	outbound   *Outbound
	activeSess atomic.Int64
}

func NewUDPManager(outbound *Outbound, timeout time.Duration) *UDPManager {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	m := &UDPManager{
		sessions: make(map[string]*UDPSession),
		timeout:  timeout,
		outbound: outbound,
	}
	go m.reaperLoop()
	return m
}

// reaperLoop 定期回收超时空闲的 UDP 会话，释放文件描述符与内存
func (m *UDPManager) reaperLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now().Unix()
		timeoutSec := int64(m.timeout.Seconds())
		m.mu.Lock()
		for key, sess := range m.sessions {
			if now-sess.lastActive.Load() > timeoutSec {
				sess.cancel()
				_ = sess.outConn.Close()
				delete(m.sessions, key)
				m.activeSess.Add(-1)
			}
		}
		m.mu.Unlock()
	}
}

// SendPacket 转发客户端的一个 UDP 数据包到目标地址
func (m *UDPManager) SendPacket(clientKey string, targetHost string, targetPort int, payload []byte, respHandler UDPResponseHandler) error {
	// SSRF 防御校验
	if m.outbound.blockPrivate {
		ips, err := net.LookupIP(targetHost)
		if err != nil {
			return fmt.Errorf("udp resolve %s: %w", targetHost, err)
		}
		for _, ip := range ips {
			if nip, err := netip.ParseAddr(ip.String()); err == nil {
				nip = nip.Unmap()
				if nip.IsLoopback() || nip.IsPrivate() || nip.IsLinkLocalUnicast() || nip.IsMulticast() {
					return errors.New("udp destination blocked by ssrf policy")
				}
			}
		}
	}

	dstAddr, err := net.ResolveUDPAddr("udp", hostPort(targetHost, targetPort))
	if err != nil {
		return fmt.Errorf("resolve udp dst %s:%d: %w", targetHost, targetPort, err)
	}

	m.mu.RLock()
	sess, ok := m.sessions[clientKey]
	m.mu.RUnlock()

	if !ok {
		// 创建新会话
		m.mu.Lock()
		sess, ok = m.sessions[clientKey]
		if !ok {
			var laddr *net.UDPAddr
			if m.outbound.bind != "" {
				if ip := net.ParseIP(m.outbound.bind); ip != nil {
					laddr = &net.UDPAddr{IP: ip}
				}
			}
			outConn, err := net.ListenUDP("udp", laddr)
			if err != nil {
				m.mu.Unlock()
				return fmt.Errorf("listen outbound udp: %w", err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			sess = &UDPSession{
				clientAddr: clientKey,
				outConn:    outConn,
				cancel:     cancel,
			}
			sess.lastActive.Store(time.Now().Unix())
			m.sessions[clientKey] = sess
			m.activeSess.Add(1)

			// 启动该会话的回包监听 goroutine
			go m.handleResponseLoop(ctx, sess, respHandler)
		}
		m.mu.Unlock()
	}

	sess.lastActive.Store(time.Now().Unix())
	stats.BytesUp.Add(int64(len(payload)))

	_, err = sess.outConn.WriteToUDP(payload, dstAddr)
	return err
}

func (m *UDPManager) handleResponseLoop(ctx context.Context, sess *UDPSession, respHandler UDPResponseHandler) {
	defer func() {
		sess.cancel()
		_ = sess.outConn.Close()
	}()

	bp := udpBufPool.Get().(*[]byte)
	defer udpBufPool.Put(bp)
	buf := *bp

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		_ = sess.outConn.SetReadDeadline(time.Now().Add(m.timeout))
		n, remoteAddr, err := sess.outConn.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				// 超时由 reaper 集中清理
				continue
			}
			return
		}

		if n > 0 {
			sess.lastActive.Store(time.Now().Unix())
			stats.BytesDown.Add(int64(n))
			rHost := remoteAddr.IP.String()
			rPort := remoteAddr.Port
			if err := respHandler(rHost, rPort, buf[:n]); err != nil {
				slog.Debug("udp response send failed", "client", sess.clientAddr, "err", err)
				return
			}
		}
	}
}

func (m *UDPManager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, sess := range m.sessions {
		sess.cancel()
		_ = sess.outConn.Close()
	}
	m.sessions = make(map[string]*UDPSession)
	m.activeSess.Store(0)
}
