package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"
)

// certLoader 支持证书热更新（例如 certbot 自动续期后无需重启服务）
type certLoader struct {
	cert, key string
	mu        sync.Mutex
	c         *tls.Certificate
	mtime     time.Time
	checked   time.Time
}

func newCertLoader(cert, key string) (*certLoader, error) {
	l := &certLoader{cert: cert, key: key}
	if _, err := l.load(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *certLoader) load() (*tls.Certificate, error) {
	c, err := tls.LoadX509KeyPair(l.cert, l.key)
	if err != nil {
		return nil, err
	}
	if st, err := os.Stat(l.cert); err == nil {
		l.mtime = st.ModTime()
	}
	l.c = &c
	return l.c, nil
}

func (l *certLoader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if time.Since(l.checked) > time.Minute {
		l.checked = time.Now()
		if st, err := os.Stat(l.cert); err == nil && st.ModTime().After(l.mtime) {
			if _, err := l.load(); err != nil {
				slog.Error("cert reload failed, keeping old cert", "err", err)
			} else {
				slog.Info("tls certificate reloaded successfully")
			}
		}
	}
	return l.c, nil
}

type trojanHandler struct {
	tlsCfg        *tls.Config
	hashes        map[string]struct{}
	fallback      string
	proxyProtocol bool
	out           *Outbound
	guard         *Guard
	lim           Limits
	udpMgr        *UDPManager
}

func newTrojanHandler(lc ListenerConfig, out *Outbound, g *Guard, lim Limits, udpMgr *UDPManager) (*trojanHandler, error) {
	var tlsCfg *tls.Config
	if lc.TLS != nil && lc.TLS.Cert != "" && lc.TLS.Key != "" {
		cl, err := newCertLoader(lc.TLS.Cert, lc.TLS.Key)
		if err != nil {
			return nil, err
		}
		// 支持 h2 与 http/1.1 双 ALPN，抗针对 HTTP 协议版本的特征扫描
		tlsCfg = &tls.Config{
			GetCertificate: cl.get,
			MinVersion:     tls.VersionTLS12,
			NextProtos:     []string{"h2", "http/1.1"},
		}
	}

	h := &trojanHandler{
		tlsCfg:        tlsCfg,
		hashes:        make(map[string]struct{}),
		fallback:      lc.Fallback,
		proxyProtocol: lc.FallbackProxyProtocol,
		out:           out,
		guard:         g,
		lim:           lim,
		udpMgr:        udpMgr,
	}
	for _, p := range lc.Passwords {
		sum := sha256.Sum224([]byte(p))
		h.hashes[hex.EncodeToString(sum[:])] = struct{}{}
	}
	return h, nil
}

func (h *trojanHandler) handle(ctx context.Context, raw net.Conn) {
	ip := addrOf(raw)
	_ = raw.SetDeadline(time.Now().Add(h.lim.HandshakeTimeout.Duration))

	var conn net.Conn = raw
	if h.tlsCfg != nil {
		tc := tls.Server(raw, h.tlsCfg)
		if err := tc.Handshake(); err != nil {
			h.guard.Fail(ip) // 非 TLS 扫描器探测
			return
		}
		conn = tc
	}
	br := bufio.NewReaderSize(conn, 8192)

	// Trojan 头部校验：56 字节 SHA-224 十六进制字符串 + CRLF
	head, _ := br.Peek(56)
	if len(head) < 56 {
		head, _ = br.Peek(br.Buffered())
	}
	if len(head) != 56 {
		h.guard.Fail(ip)
		h.doFallback(ctx, raw, conn, br)
		return
	}
	if _, ok := h.hashes[string(head)]; !ok {
		h.guard.Fail(ip)
		h.doFallback(ctx, raw, conn, br)
		return
	}
	_, _ = br.Discard(56)

	var crlf [2]byte
	if _, err := io.ReadFull(br, crlf[:]); err != nil || crlf != [2]byte{'\r', '\n'} {
		h.guard.Fail(ip)
		return
	}

	cmd, err := br.ReadByte()
	if err != nil {
		return
	}
	host, port, err := readAddr(br)
	if err != nil {
		h.guard.Fail(ip)
		return
	}
	if _, err := io.ReadFull(br, crlf[:]); err != nil || crlf != [2]byte{'\r', '\n'} {
		h.guard.Fail(ip)
		return
	}

	switch cmd {
	case 0x01: // TCP CONNECT
		dctx, cancel := context.WithTimeout(ctx, h.lim.HandshakeTimeout.Duration)
		up, err := h.out.Dial(dctx, host, port)
		cancel()
		if err != nil {
			slog.Debug("trojan dial failed", "target", hostPort(host, port), "err", err)
			return
		}
		_ = conn.SetDeadline(time.Time{})
		relay(&bufConn{Conn: conn, r: br}, up, h.lim.IdleTimeout.Duration)

	case 0x03: // UDP ASSOCIATE (通过 TLS 流多路复用传输 Trojan UDP 帧)
		_ = conn.SetDeadline(time.Time{})
		h.handleTrojanUDP(ctx, conn, br)

	default:
		h.guard.Fail(ip)
	}
}

// handleTrojanUDP 处理 Trojan 原生 UDP 帧：
// 客户端帧格式: [ATYP + ADDR + PORT] [Length 2B] [\r\n] [Payload]
// 服务端回传帧格式: [ATYP + ADDR + PORT] [Length 2B] [\r\n] [Payload]
func (h *trojanHandler) handleTrojanUDP(ctx context.Context, tc net.Conn, br *bufio.Reader) {
	clientKey := fmt.Sprintf("trojan:%s", tc.RemoteAddr().String())
	defer h.udpMgr.RemoveSession(clientKey)
	var writeMu sync.Mutex

	for {
		_ = tc.SetReadDeadline(time.Now().Add(h.lim.IdleTimeout.Duration))
		tHost, tPort, err := readAddr(br)
		if err != nil {
			return
		}
		var lenBytes [2]byte
		if _, err := io.ReadFull(br, lenBytes[:]); err != nil {
			return
		}
		payloadLen := int(binary.BigEndian.Uint16(lenBytes[:]))

		var crlf [2]byte
		if _, err := io.ReadFull(br, crlf[:]); err != nil || crlf != [2]byte{'\r', '\n'} {
			return
		}
		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(br, payload); err != nil {
			return
		}

		_ = h.udpMgr.SendPacket(clientKey, tHost, tPort, payload, func(respHost string, respPort int, respPayload []byte) error {
			writeMu.Lock()
			defer writeMu.Unlock()

			// 组装 Trojan UDP 响应帧
			addrHeader, err := writeAddr(nil, respHost, respPort)
			if err != nil {
				return err
			}
			var lBytes [2]byte
			binary.BigEndian.PutUint16(lBytes[:], uint16(len(respPayload)))

			_ = tc.SetWriteDeadline(time.Now().Add(h.lim.IdleTimeout.Duration))
			if _, err := tc.Write(addrHeader); err != nil {
				return err
			}
			if _, err := tc.Write(lBytes[:]); err != nil {
				return err
			}
			if _, err := tc.Write([]byte{'\r', '\n'}); err != nil {
				return err
			}
			_, err = tc.Write(respPayload)
			return err
		})
	}
}

// doFallback 将探测流量原样交由真实后端 Web 站点处理，并支持 PROXY protocol v1
func (h *trojanHandler) doFallback(ctx context.Context, raw net.Conn, tc net.Conn, br *bufio.Reader) {
	if h.fallback == "" {
		return
	}
	d := net.Dialer{Timeout: 3 * time.Second}
	fb, err := d.DialContext(ctx, "tcp", h.fallback)
	if err != nil {
		return
	}
	// 如果配置了 PROXY 协议，先向后端发送真实的客户端源地址
	if h.proxyProtocol {
		hdr := buildProxyProtocolV1Header(raw.RemoteAddr(), raw.LocalAddr())
		_, _ = fb.Write(hdr)
	}
	_ = tc.SetDeadline(time.Time{})
	relay(&bufConn{Conn: tc, r: br}, fb, h.lim.IdleTimeout.Duration)
}
