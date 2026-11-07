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

// certLoader 支持证书热更新（例如 acme.sh 自动续期后无需重启服务）
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
		tlsCfg = &tls.Config{
			GetCertificate: cl.get,
			MinVersion:     tls.VersionTLS12,
			NextProtos:     []string{"http/1.1"},
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			},
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
			return
		}
		conn = tc
	}
	br := acquireReader(conn)
	defer releaseReader(br)

	if _, err := br.Peek(1); err != nil {
		return
	}
	if peek4, err := br.Peek(4); err == nil && isHTTPMethodPrefix(peek4) {
		h.doFallback(ctx, raw, conn, br)
		return
	}

	// Trojan 头部校验：56 字节 SHA-224 十六进制字符串 + CRLF
	head, err := br.Peek(56)
	if err != nil {
		h.doFallback(ctx, raw, conn, br)
		return
	}
	if _, ok := h.hashes[string(head)]; !ok {
		h.guard.Fail(ip)
		h.doFallback(ctx, raw, conn, br)
		return
	}
	h.guard.AuthSuccess(ip)
	_, _ = br.Discard(56)

	var crlf [2]byte
	if _, err := io.ReadFull(br, crlf[:]); err != nil || crlf != [2]byte{'\r', '\n'} {
		return
	}

	cmd, err := br.ReadByte()
	if err != nil {
		return
	}
	host, port, err := readAddr(br)
	if err != nil {
		return
	}
	if _, err := io.ReadFull(br, crlf[:]); err != nil || crlf != [2]byte{'\r', '\n'} {
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

	case 0x03: // UDP ASSOCIATE
		_ = conn.SetDeadline(time.Time{})
		if h.udpMgr != nil {
			h.handleTrojanUDP(ctx, conn, br)
		}
	}
}

// handleTrojanUDP 处理 Trojan 原生 UDP 帧（合并单次 Write 消除多余 TLS Record 开销）
func (h *trojanHandler) handleTrojanUDP(ctx context.Context, tc net.Conn, br *bufio.Reader) {
	clientKey := fmt.Sprintf("trojan:%d", udpSeq.Add(1))
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
			if len(respPayload) > 65535 {
				return nil
			}
			pkt := make([]byte, 0, 24+len(respPayload))
			var err error
			pkt, err = writeAddr(pkt, respHost, respPort)
			if err != nil {
				return err
			}
			var lBytes [2]byte
			binary.BigEndian.PutUint16(lBytes[:], uint16(len(respPayload)))
			pkt = append(pkt, lBytes[0], lBytes[1], '\r', '\n')
			pkt = append(pkt, respPayload...)

			writeMu.Lock()
			defer writeMu.Unlock()
			_ = tc.SetWriteDeadline(time.Now().Add(h.lim.IdleTimeout.Duration))
			_, err = tc.Write(pkt)
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
	if h.proxyProtocol {
		hdr := buildProxyProtocolV1Header(raw.RemoteAddr(), raw.LocalAddr())
		_, _ = fb.Write(hdr)
	}
	_ = tc.SetDeadline(time.Time{})
	relay(&bufConn{Conn: tc, r: br}, fb, h.lim.IdleTimeout.Duration)
}
