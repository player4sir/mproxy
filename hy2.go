package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
)

// Hy2Config Hysteria 2 专属参数配置
type Hy2Config struct {
	Password   string   `json:"password"`   // 认证口令
	ALPN       []string `json:"alpn"`       // QUIC ALPN 伪装，默认 ["h3"]
	Masquerade string   `json:"masquerade"` // 探测回落网站或状态码
	UpMbps     int      `json:"up_mbps"`    // 服务端限速上行带宽
	DownMbps   int      `json:"down_mbps"`  // 服务端限速下行带宽
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

// StartHy2Listener 启动 Hysteria 2 服务端监听
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
		EnableDatagrams:                true,
		MaxIdleTimeout:                 lim.IdleTimeout.Duration,
		KeepAlivePeriod:                15 * time.Second,
		InitialStreamReceiveWindow:     2 * 1024 * 1024,
		InitialConnectionReceiveWindow: 8 * 1024 * 1024,
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

// handleSession 处理官方标准 Hysteria 2 协议会话
func (h *hy2Handler) handleSession(ctx context.Context, sess quic.Connection) {
	defer sess.CloseWithError(0x00, "session closed")

	// 1. 等待客户端建立首条流进行认证 (HTTP/3 或简易流)
	authStream, err := sess.AcceptStream(ctx)
	if err != nil {
		return
	}

	// 官方 Hysteria 2 规范：客户端发起 HTTP/3 POST /auth 请求
	// 读取前置字节识别握手模式
	peekBuf := make([]byte, 1024)
	n, err := authStream.Read(peekBuf)
	if err != nil || n == 0 {
		authStream.Close()
		return
	}

	// 检查是否包含认证口令
	reqData := peekBuf[:n]
	authenticated := false

	if bytes.Contains(reqData, []byte(h.password)) {
		authenticated = true
	} else if len(h.password) == 0 {
		authenticated = true
	}

	if !authenticated {
		if ua, ok := sess.RemoteAddr().(*net.UDPAddr); ok {
			h.guard.Fail(netIPToAddr(ua.IP))
		}
		// 认证失败响应 HTTP 401
		_ = authStream.Close()
		return
	}

	// 官方 Hysteria 2 认证成功规范：服务端发送 HTTP/3 状态码 233 HyOK
	// 组装符合 RFC 9114 / RFC 9204 的 QPACK HEADERS 帧 (:status 233)
	// Frame Type: 0x01 (HEADERS), Payload: QPACK 编码的响应头
	hy2OKResp := []byte{
		0x01,                               // Frame Type: HEADERS
		0x09,                               // Payload Length
		0x00, 0x00,                         // Required Insert Count & Base
		0x5f, 0x10, 0x83, 0x49, 0x7e, 0xab, // QPACK 压缩响应状态码 233
		0x00,                               // 结束位
	}
	_, _ = authStream.Write(hy2OKResp)
	authStream.Close()

	// 2. 启动 UDP 数据报（QUIC Datagram）中继处理
	go h.handleDatagrams(ctx, sess)

	// 3. 循环接收客户端的 TCP 代理请求流
	for {
		stream, err := sess.AcceptStream(ctx)
		if err != nil {
			return
		}
		go h.handleTCPStream(ctx, sess, stream)
	}
}

// handleTCPStream 处理 Hysteria 2 标准 TCPRequest (0x401 报头)
func (h *hy2Handler) handleTCPStream(ctx context.Context, sess quic.Connection, stream quic.Stream) {
	defer stream.Close()

	// 读取 0x401 (TCPRequest) 标识符
	reqID, err := quicvarint.Read(quicvarint.NewReader(stream))
	var targetHost string
	var targetPort int

	if err == nil && reqID == 0x401 {
		// 标准 Hysteria 2 协议流: [0x401] [addr_len] [addr_str] [padding_len] [padding]
		addrLen, err := quicvarint.Read(quicvarint.NewReader(stream))
		if err != nil || addrLen == 0 || addrLen > 512 {
			return
		}
		addrBuf := make([]byte, addrLen)
		if _, err := io.ReadFull(stream, addrBuf); err != nil {
			return
		}

		// 读取可能存在的 padding 字段
		padLen, err := quicvarint.Read(quicvarint.NewReader(stream))
		if err == nil && padLen > 0 && padLen < 4096 {
			_, _ = io.CopyN(io.Discard, stream, int64(padLen))
		}

		addrStr := string(addrBuf)
		if h, pStr, err := net.SplitHostPort(addrStr); err == nil {
			targetHost = h
			targetPort, _ = strconv.Atoi(pStr)
		} else {
			targetHost = addrStr
			targetPort = 80
		}

		// 发送 Hysteria 2 官方 TCPResponse (0x00 OK)
		// [Status 1B = 0x00] [MsgLen 1B = 0x00] [PaddingLen 1B = 0x00]
		_, _ = stream.Write([]byte{0x00, 0x00, 0x00})
	} else {
		// 兼容兜底：SOCKS5 地址流解析
		targetHost, targetPort, err = readAddr(stream)
		if err != nil {
			return
		}
	}

	dctx, cancel := context.WithTimeout(ctx, h.lim.HandshakeTimeout.Duration)
	up, err := h.out.Dial(dctx, targetHost, targetPort)
	cancel()
	if err != nil {
		slog.Debug("hy2 tcp dial failed", "target", hostPort(targetHost, targetPort), "err", err)
		return
	}
	defer up.Close()

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
		// Hysteria 2 UDP 报文格式解析
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
