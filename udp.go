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

var (
	udpSeq     atomic.Uint64
	udpBufPool = sync.Pool{
		New: func() any {
			b := make([]byte, 65535)
			return &b
		},
	}
)

type UDPSession struct {
	clientAddr string
	outConn    *net.UDPConn
	lastActive atomic.Int64 // unix timestamp in seconds
	cancel     context.CancelFunc
	handlerMu  sync.RWMutex
	handler    UDPResponseHandler
}

// UDPResponseHandler 将出站目标回包重新组装为特定协议格式并送回客户端
type UDPResponseHandler func(targetHost string, targetPort int, payload []byte) error

type UDPManager struct {
	mu         sync.RWMutex
	sessions   map[string]*UDPSession
	timeout    time.Duration
	outbound   *Outbound
	activeSess atomic.Int64
	stop       chan struct{}
	closed     atomic.Bool
}

func NewUDPManager(outbound *Outbound, timeout time.Duration) *UDPManager {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	m := &UDPManager{
		sessions: make(map[string]*UDPSession),
		timeout:  timeout,
		outbound: outbound,
		stop:     make(chan struct{}),
	}
	go m.reaperLoop()
	return m
}

// reaperLoop 定期回收超时空闲的 UDP 会话，释放文件描述符与内存
func (m *UDPManager) reaperLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-ticker.C:
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
}

// RemoveSession 手动释放特定客户端或流关联的 UDP 会话
func (m *UDPManager) RemoveSession(clientKey string) {
	m.mu.Lock()
	if sess, ok := m.sessions[clientKey]; ok {
		sess.cancel()
		_ = sess.outConn.Close()
		delete(m.sessions, clientKey)
		m.activeSess.Add(-1)
	}
	m.mu.Unlock()
}

// SendPacket 转发客户端的一个 UDP 数据包到目标地址
func (m *UDPManager) SendPacket(clientKey string, targetHost string, targetPort int, payload []byte, respHandler UDPResponseHandler) error {
	rctx, rcancel := context.WithTimeout(context.Background(), 3*time.Second)
	ips, err := m.outbound.ResolveTarget(rctx, targetHost)
	rcancel()
	if err != nil {
		return fmt.Errorf("resolve udp dst %s: %w", targetHost, err)
	}

	dstIP := ips[0]
	for _, candidate := range ips {
		if ip4 := candidate.To4(); ip4 != nil {
			dstIP = ip4
			break
		}
	}
	dstAddr := &net.UDPAddr{IP: dstIP, Port: targetPort}

	m.mu.RLock()
	sess, ok := m.sessions[clientKey]
	m.mu.RUnlock()

	if !ok {
		m.mu.Lock()
		sess, ok = m.sessions[clientKey]
		if !ok {
			var laddr *net.UDPAddr
			if m.outbound.bind != "" {
				if ip := net.ParseIP(m.outbound.bind); ip != nil {
					laddr = &net.UDPAddr{IP: ip}
				}
			}
			udpNet := "udp4"
			if dstIP.To4() == nil || m.outbound.hasIPv6 {
				udpNet = "udp"
			}
			outConn, err := net.ListenUDP(udpNet, laddr)
			if err != nil {
				m.mu.Unlock()
				return fmt.Errorf("listen outbound udp: %w", err)
			}
			_ = outConn.SetReadBuffer(2 * 1024 * 1024)
			_ = outConn.SetWriteBuffer(2 * 1024 * 1024)

			ctx, cancel := context.WithCancel(context.Background())
			sess = &UDPSession{
				clientAddr: clientKey,
				outConn:    outConn,
				cancel:     cancel,
				handler:    respHandler,
			}
			sess.lastActive.Store(time.Now().Unix())
			m.sessions[clientKey] = sess
			m.activeSess.Add(1)

			go m.handleResponseLoop(ctx, sess)
		}
		m.mu.Unlock()
	}

	if respHandler != nil {
		sess.handlerMu.Lock()
		sess.handler = respHandler
		sess.handlerMu.Unlock()
	}

	sess.lastActive.Store(time.Now().Unix())
	stats.BytesUp.Add(int64(len(payload)))

	_, err = sess.outConn.WriteToUDP(payload, dstAddr)
	return err
}

func (m *UDPManager) handleResponseLoop(ctx context.Context, sess *UDPSession) {
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
				continue
			}
			return
		}

		if n > 0 {
			sess.lastActive.Store(time.Now().Unix())
			stats.BytesDown.Add(int64(n))
			rHost := remoteAddr.IP.String()
			if nip, ok := netip.AddrFromSlice(remoteAddr.IP); ok {
				rHost = nip.Unmap().String()
			}
			rPort := remoteAddr.Port

			sess.handlerMu.RLock()
			handler := sess.handler
			sess.handlerMu.RUnlock()

			if handler != nil {
				if err := handler(rHost, rPort, buf[:n]); err != nil {
					slog.Debug("udp response send failed", "client", sess.clientAddr, "err", err)
					return
				}
			}
		}
	}
}

func (m *UDPManager) Close() {
	if m.closed.CompareAndSwap(false, true) {
		close(m.stop)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, sess := range m.sessions {
		sess.cancel()
		_ = sess.outConn.Close()
	}
	m.sessions = make(map[string]*UDPSession)
	m.activeSess.Store(0)
}
