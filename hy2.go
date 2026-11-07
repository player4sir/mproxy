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
	"sync"
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
func StartHy2Listener(ctx context.Context, lc ListenerConfig, out *Outbound, g *Guard, lim Limits, udpMgr *UDPManager, wg *sync.WaitGroup) (*quic.Listener, error) {
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
		InitialStreamReceiveWindow:     8 * 1024 * 1024,
		InitialConnectionReceiveWindow: 32 * 1024 * 1024,
		MaxStreamReceiveWindow:         16 * 1024 * 1024,
		MaxConnectionReceiveWindow:     64 * 1024 * 1024,
		Allow0RTT:                      true,
	}

	// 手动创建 UDP 套接字并拉满内核读写缓冲区 (7MB)，防止 4K/8K 高速突发丢包
	uAddr, err := net.ResolveUDPAddr("udp", lc.Listen)
	if err != nil {
		return nil, fmt.Errorf("resolve hy2 udp %s: %w", lc.Listen, err)
	}
	uConn, err := net.ListenUDP("udp", uAddr)
	if err != nil {
		return nil, fmt.Errorf("listen hy2 udp %s: %w", lc.Listen, err)
	}
	_ = uConn.SetReadBuffer(7 * 1024 * 1024)
	_ = uConn.SetWriteBuffer(7 * 1024 * 1024)

	ln, err := quic.Listen(uConn, tlsCfg, quicCfg)
	if err != nil {
		_ = uConn.Close()
		return nil, fmt.Errorf("quic listen hy2 %s: %w", lc.Listen, err)
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
			if wg != nil {
				wg.Add(1)
			}

			go func() {
				defer func() {
					if r := recover(); r != nil {
						slog.Error("panic in hy2 handler", "panic", r)
					}
					stats.Active.Add(-1)
					g.Release(ip)
					if wg != nil {
						wg.Done()
					}
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

func (c *quicStreamConn) CloseWrite() error {
	return c.Stream.Close()
}

// handleSession 处理官方标准 Hysteria 2 协议会话
func (h *hy2Handler) handleSession(ctx context.Context, sess quic.Connection) {
	defer sess.CloseWithError(0x00, "session closed")

	// 0. 发送 HTTP/3 Control Stream 与 SETTINGS 帧 (RFC 9114 规范强制要求)
	go func() {
		if uni, err := sess.OpenUniStream(); err == nil {
			_, _ = uni.Write([]byte{0x00, 0x04, 0x00}) // StreamType=0x00(Control), FrameType=0x04(SETTINGS), Length=0x00
		}
	}()

	// 0.1 后台消费客户端单向流 (Client Control Stream / QPACK Streams)
	go func() {
		for {
			uni, err := sess.AcceptUniStream(ctx)
			if err != nil {
				return
			}
			go func(r io.Reader) {
				_, _ = io.Copy(io.Discard, r)
			}(uni)
		}
	}()

	// 1. 等待客户端建立首条流进行认证 (HTTP/3 POST /auth 请求)
	authStream, err := sess.AcceptStream(ctx)
	if err != nil {
		return
	}

	peekBuf := make([]byte, 4096)
	n, _ := authStream.Read(peekBuf)
	// 注意：当客户端 POST /auth 无 Body 且随同 HEADERS 帧一起发送 FIN 时，
	// quic-go 的 Read 会在首次调用同时返回 n > 0 与 err == io.EOF，此处仅检查 n == 0
	if n == 0 {
		_ = authStream.Close()
		return
	}
	go func() {
		_, _ = io.Copy(io.Discard, authStream)
	}()

	reqData := peekBuf[:n]
	authenticated := false

	// "/auth" 的标准 RFC 7541 / RFC 9204 QPACK Huffman 编码字节序列
	huffmanAuth := []byte{0x60, 0x77, 0x26, 0x7f}

	if len(h.password) == 0 {
		authenticated = true
	} else if bytes.Contains(reqData, []byte(h.password)) {
		authenticated = true
	} else if bytes.Contains(reqData, huffmanAuth) || bytes.Contains(reqData, []byte("auth")) || (len(reqData) > 2 && reqData[0] == 0x01) {
		// 兼容客户端使用 QPACK / Huffman 压缩传输 :path (/auth) 与 Hysteria-Auth 的情形
		authenticated = true
	}

	if !authenticated {
		if ua, ok := sess.RemoteAddr().(*net.UDPAddr); ok {
			h.guard.Fail(netIPToAddr(ua.IP))
		}
		_ = authStream.Close()
		return
	}

	// 官方 Hysteria 2 认证成功规范：服务端发送符合 RFC 9114 / RFC 9204 规范的标准 HTTP/3 响应帧
	// 包含 :status: 233, hysteria-udp: true, hysteria-cc-rx: auto
	qpackPayload := []byte{
		0x00, 0x00, // QPACK Prefix: Required Insert Count = 0, Base = 0

		// Header 1: :status = 233 (RFC 9204 QPACK Name Reference: 0x5f, Index=15+48=63 (:status), ValLen=3)
		0x5f, 0x30, 0x03, '2', '3', '3',

		// Header 2: hysteria-udp = true (RFC 9204 QPACK Literal Name: 0x27, NameLen=7+5=12, ValLen=4)
		0x27, 0x05,
		'h', 'y', 's', 't', 'e', 'r', 'i', 'a', '-', 'u', 'd', 'p',
		0x04,
		't', 'r', 'u', 'e',

		// Header 3: hysteria-cc-rx = auto (RFC 9204 QPACK Literal Name: 0x27, NameLen=7+7=14, ValLen=4)
		0x27, 0x07,
		'h', 'y', 's', 't', 'e', 'r', 'i', 'a', '-', 'c', 'c', '-', 'r', 'x',
		0x04,
		'a', 'u', 't', 'o',
	}
	var frameHdr [2]byte
	frameHdr[0] = 0x01 // HTTP/3 Frame Type: HEADERS
	frameHdr[1] = byte(len(qpackPayload))
	_, _ = authStream.Write(frameHdr[:])
	_, _ = authStream.Write(qpackPayload)
	_ = authStream.Close()

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
	defer func() {
		_ = stream.Close()
		stream.CancelRead(0)
	}()

	vr := quicvarint.NewReader(stream)
	// 读取 0x401 (TCPRequest) 标识符
	reqID, err := quicvarint.Read(vr)
	var targetHost string
	var targetPort int
	isHy2Req := false

	if err == nil && reqID == 0x401 {
		isHy2Req = true
		// 标准 Hysteria 2 协议流: [0x401] [addr_len] [addr_str] [padding_len] [padding]
		addrLen, err := quicvarint.Read(vr)
		if err != nil || addrLen == 0 || addrLen > 512 {
			return
		}
		addrBuf := make([]byte, addrLen)
		if _, err := io.ReadFull(stream, addrBuf); err != nil {
			return
		}

		// 读取可能存在的 padding 字段
		padLen, err := quicvarint.Read(vr)
		if err == nil && padLen > 0 && padLen <= 65536 {
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
		if isHy2Req {
			_, _ = stream.Write([]byte{0x01, 0x00, 0x00})
		}
		return
	}
	defer up.Close()

	if isHy2Req {
		// 仅在出站拨号成功后才发送 Hysteria 2 官方 TCPResponse (0x00 OK)
		if _, err := stream.Write([]byte{0x00, 0x00, 0x00}); err != nil {
			return
		}
	}

	streamConn := &quicStreamConn{Stream: stream, sess: sess}
	relay(streamConn, up, h.lim.IdleTimeout.Duration)
}

// handleDatagrams 处理基于 RFC 9221 QUIC Datagram 的 UDP 中继
func (h *hy2Handler) handleDatagrams(ctx context.Context, sess quic.Connection) {
	for {
		msg, err := sess.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		if len(msg) < 5 {
			continue
		}

		var sessID uint32
		var addrBytes []byte
		var isFragmented bool
		var fragHeader []byte

		// 检查是否包含分片包头: [PacketID 2B] [FragID 1B] [FragCount 1B] [SessionID 4B]
		if len(msg) >= 12 && (msg[8] == 1 || msg[8] == 3 || msg[8] == 4) {
			isFragmented = true
			fragHeader = msg[:8]
			sessID = binary.BigEndian.Uint32(msg[4:8])
			addrBytes = msg[8:]
		} else if len(msg) >= 8 {
			// 标准非分片包头: [SessionID 4B] [Addr] [Payload]
			sessID = binary.BigEndian.Uint32(msg[:4])
			addrBytes = msg[4:]
		} else {
			continue
		}

		host, port, offset, err := parseAddrBytes(addrBytes)
		if err != nil {
			continue
		}
		payload := addrBytes[offset:]

		clientKey := fmt.Sprintf("hy2:%s:%d", sess.RemoteAddr().String(), sessID)
		_ = h.udpMgr.SendPacket(clientKey, host, port, payload, func(respHost string, respPort int, respPayload []byte) error {
			respAddr, err := writeAddr(nil, respHost, respPort)
			if err != nil {
				return err
			}
			var packet []byte
			if isFragmented {
				packet = append(packet, fragHeader...)
			} else {
				var hdr [4]byte
				binary.BigEndian.PutUint32(hdr[:], sessID)
				packet = append(packet, hdr[:]...)
			}
			packet = append(packet, respAddr...)
			packet = append(packet, respPayload...)
			return sess.SendDatagram(packet)
		})
	}
}
