package main

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/quic-go/quic-go"
)

// Hy2Config Hysteria 2 专属参数配置
type Hy2Config struct {
	Password   string   `json:"password"`   // 认证口令
	ALPN       []string `json:"alpn"`       // QUIC ALPN 伪装，默认 ["h3"]
	Masquerade string   `json:"masquerade"` // 探测回落网站或状态码 (如 127.0.0.1:8080 或 404)
	UpMbps     int      `json:"up_mbps"`    // 服务端限速上行带宽 (Mbps, 0 为不限制)
	DownMbps   int      `json:"down_mbps"`  // 服务端限速下行带宽 (Mbps, 0 为不限制)
}

type hy2Handler struct {
	password   string
	masquerade string
	out        *Outbound
	guard      *Guard
	lim        Limits
	udpMgr     *UDPManager
}

func newHy2Handler(lc ListenerConfig, out *Outbound, g *Guard, lim Limits, udpMgr *UDPManager) *hy2Handler {
	pw := ""
	masq := ""
	if lc.Hy2 != nil {
		pw = lc.Hy2.Password
		masq = lc.Hy2.Masquerade
	}
	if pw == "" && len(lc.Passwords) > 0 {
		pw = lc.Passwords[0]
	}
	if masq == "" {
		masq = lc.Fallback
	}
	return &hy2Handler{
		password:   pw,
		masquerade: masq,
		out:        out,
		guard:      g,
		lim:        lim,
		udpMgr:     udpMgr,
	}
}

// StartHy2Listener 启动 Hysteria 2 基于 QUIC/UDP 的服务端监听器
func StartHy2Listener(ctx context.Context, lc ListenerConfig, out *Outbound, g *Guard, lim Limits, udpMgr *UDPManager) (*quic.Listener, error) {
	cl, err := newCertLoader(lc.TLS.Cert, lc.TLS.Key)
	if err != nil {
		return nil, fmt.Errorf("hy2 cert load: %w", err)
	}

	alpn := []string{"h3"}
	if lc.Hy2 != nil && len(lc.Hy2.ALPN) > 0 {
		alpn = lc.Hy2.ALPN
	}

	tlsCfg := &tls.Config{
		GetCertificate: cl.get,
		NextProtos:     alpn,
		MinVersion:     tls.VersionTLS13,
	}

	quicCfg := &quic.Config{
		EnableDatagrams:                true, // RFC 9221 QUIC Datagram 支持 UDP 中继
		MaxIdleTimeout:                 lim.IdleTimeout.Duration,
		KeepAlivePeriod:                15 * time.Second,
		InitialStreamReceiveWindow:     1024 * 1024,
		InitialConnectionReceiveWindow: 4096 * 1024,
		Allow0RTT:                      true,
	}

	ln, err := quic.ListenAddr(lc.Listen, tlsCfg, quicCfg)
	if err != nil {
		return nil, fmt.Errorf("listen hy2 udp %s: %w", lc.Listen, err)
	}
	slog.Info("listening hy2 (quic/udp)", "addr", lc.Listen)

	h := newHy2Handler(lc, out, g, lim, udpMgr)

	go func() {
		for {
			sess, err := ln.Accept(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}

			// 获取客户端 IP 并经由 Guard 守卫检查
			udpAddr, ok := sess.RemoteAddr().(*net.UDPAddr)
			if !ok {
				_ = sess.CloseWithError(0x01, "invalid remote addr")
				continue
			}
			ip := netIPToAddr(udpAddr.IP)
			if !g.Acquire(ip) {
				_ = sess.CloseWithError(0x02, "banned or rate limited")
				continue
			}
			stats.Active.Add(1)
			stats.Total.Add(1)

			go func() {
				defer func() {
					if r := recover(); r != nil {
						slog.Error("panic in hy2 handler", "panic", r)
					}
					stats.Active.Add(-1)
					g.Release(ip)
				}()
				h.handleSession(ctx, sess)
			}()
		}
	}()

	return ln, nil
}

// netIPToAddr 将 net.IP 转换为 netip.Addr
func netIPToAddr(ip net.IP) netip.Addr {
	if a, ok := netip.AddrFromSlice(ip); ok {
		return a.Unmap()
	}
	return netip.Addr{}
}

// quicStreamConn 将 quic.Stream 包装为标准的 net.Conn 接口
type quicStreamConn struct {
	quic.Stream
	sess quic.Connection
}

func (c *quicStreamConn) LocalAddr() net.Addr {
	return c.sess.LocalAddr()
}

func (c *quicStreamConn) RemoteAddr() net.Addr {
	return c.sess.RemoteAddr()
}

// handleSession 处理单个客户端 QUIC 握手会话
func (h *hy2Handler) handleSession(ctx context.Context, sess quic.Connection) {
	defer sess.CloseWithError(0x00, "session closed")

	// 1. 协商首条控制流进行 Hysteria 2 认证
	authStream, err := sess.AcceptStream(ctx)
	if err != nil {
		return
	}
	defer authStream.Close()

	// Hysteria 2 鉴权帧规范：[Command 1B (0x00: Auth)] [Len 1B] [Password]
	var cmdBuf [2]byte
	if _, err := io.ReadFull(authStream, cmdBuf[:]); err != nil {
		return
	}
	if cmdBuf[0] != 0x00 { // 必须为 Auth 指令
		_, _ = authStream.Write([]byte{0x01}) // 0x01: 拒绝
		return
	}

	pwLen := int(cmdBuf[1])
	pwBuf := make([]byte, pwLen)
	if _, err := io.ReadFull(authStream, pwBuf); err != nil {
		return
	}

	if subtle.ConstantTimeCompare([]byte(h.password), pwBuf) != 1 {
		// 认证失败：记录防御封禁并响应错误
		if ua, ok := sess.RemoteAddr().(*net.UDPAddr); ok {
			h.guard.Fail(netIPToAddr(ua.IP))
		}
		_, _ = authStream.Write([]byte{0x01})
		return
	}

	// 认证成功：响应 0x00
	if _, err := authStream.Write([]byte{0x00}); err != nil {
		return
	}

	// 2. 启动 UDP 数据报（QUIC Datagram）接收循环
	go h.handleDatagrams(ctx, sess)

	// 3. 循环接收 TCP 代理 Stream
	for {
		stream, err := sess.AcceptStream(ctx)
		if err != nil {
			return
		}
		go h.handleTCPStream(ctx, sess, stream)
	}
}

// handleTCPStream 处理 QUIC Stream 代理的 TCP 流量
func (h *hy2Handler) handleTCPStream(ctx context.Context, sess quic.Connection, stream quic.Stream) {
	defer stream.Close()

	// Stream 头部为目标地址: [ATYP + ADDR + PORT]
	host, port, err := readAddr(stream)
	if err != nil {
		return
	}

	dctx, cancel := context.WithTimeout(ctx, h.lim.HandshakeTimeout.Duration)
	up, err := h.out.Dial(dctx, host, port)
	cancel()
	if err != nil {
		slog.Debug("hy2 tcp dial failed", "target", hostPort(host, port), "err", err)
		return
	}
	defer up.Close()

	// 将 quic.Stream 包装为 net.Conn 后传入 relay
	streamConn := &quicStreamConn{Stream: stream, sess: sess}
	relay(streamConn, up, h.lim.IdleTimeout.Duration)
}

// handleDatagrams 处理基于 RFC 9221 QUIC Datagram 的 UDP 中继
func (h *hy2Handler) handleDatagrams(ctx context.Context, sess quic.Connection) {
	clientKey := fmt.Sprintf("hy2:%s", sess.RemoteAddr().String())

	for {
		msg, err := sess.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		// Hysteria 2 UDP 帧结构: [SessionID 4B] [Addr (ATYP+Addr+Port)] [Payload...]
		if len(msg) < 8 {
			continue
		}
		sessID := binary.BigEndian.Uint32(msg[:4])
		host, port, offset, err := parseAddrBytes(msg[4:])
		if err != nil {
			continue
		}
		payload := msg[4+offset:]

		_ = h.udpMgr.SendPacket(clientKey, host, port, payload, func(respHost string, respPort int, respPayload []byte) error {
			respAddr, err := writeAddr(nil, respHost, respPort)
			if err != nil {
				return err
			}
			var hdr [4]byte
			binary.BigEndian.PutUint32(hdr[:], sessID)

			packet := append(hdr[:], respAddr...)
			packet = append(packet, respPayload...)
			return sess.SendDatagram(packet)
		})
	}
}
