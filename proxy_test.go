package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testLimits() Limits {
	l := Limits{MaxConns: 200, MaxConnsPerIP: 200, BanAfterFailures: 1000}
	l.IdleTimeout.Duration = 5 * time.Second
	l.HandshakeTimeout.Duration = 3 * time.Second
	l.BanDuration.Duration = time.Minute
	return l
}

func startEchoTCP(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String()
}

func startEchoUDP(t *testing.T) (*net.UDPConn, string) {
	uaddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", uaddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, raddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(buf[:n], raddr)
		}
	}()
	return conn, conn.LocalAddr().String()
}

func startServer(t *testing.T, h Handler, lim Limits) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{name: "test", ln: ln, guard: NewGuard(lim), h: h, wg: &wg}
	go s.Serve(ctx)
	t.Cleanup(func() {
		cancel()
		ln.Close()
		wg.Wait()
	})
	return ln.Addr().String()
}

func newOut(t *testing.T) *Outbound {
	o, err := NewOutbound(OutboundConfig{DialTimeout: Duration{3 * time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func addrBytes(t *testing.T, hp string) []byte {
	h, p, _ := net.SplitHostPort(hp)
	ip := net.ParseIP(h).To4()
	var pn int
	for _, ch := range p {
		pn = pn*10 + int(ch-'0')
	}
	return append(append([]byte{1}, ip...), byte(pn>>8), byte(pn))
}

func expectEcho(t *testing.T, c net.Conn, msg string) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != msg {
		t.Fatalf("echo mismatch: got %q, want %q, err=%v", buf, msg, err)
	}
}

func selfSigned(t *testing.T) (string, string) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	kb, _ := x509.MarshalECPrivateKey(k)
	dir := t.TempDir()
	cp, kp := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	_ = os.WriteFile(cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600)
	_ = os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0600)
	return cp, kp
}

func TestSocks5TCPAndUDP(t *testing.T) {
	echoTCP := startEchoTCP(t)
	_, echoUDP := startEchoUDP(t)
	lim := testLimits()
	out := newOut(t)
	udpMgr := NewUDPManager(out, 5*time.Second)
	t.Cleanup(func() { udpMgr.Close() })

	h := &socks5Handler{
		users:  map[string]string{"user": "pass"},
		out:    out,
		guard:  NewGuard(lim),
		lim:    lim,
		udpMgr: udpMgr,
	}
	srv := startServer(t, h.handle, lim)

	// 1. SOCKS5 TCP
	c, err := net.Dial("tcp", srv)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	_, _ = c.Write([]byte{5, 1, 2})
	r := make([]byte, 2)
	_, _ = io.ReadFull(c, r)
	if r[1] != 2 {
		t.Fatalf("socks5 method neg failed: %v", r)
	}
	_, _ = c.Write([]byte{1, 4, 'u', 's', 'e', 'r', 4, 'p', 'a', 's', 's'})
	_, _ = io.ReadFull(c, r)
	if r[1] != 0 {
		t.Fatal("socks5 auth failed")
	}

	_, _ = c.Write(append([]byte{5, 1, 0}, addrBytes(t, echoTCP)...))
	rep := make([]byte, 10)
	_, _ = io.ReadFull(c, rep)
	if rep[1] != 0 {
		t.Fatalf("socks5 connect reply error: %v", rep)
	}
	expectEcho(t, c, "hello socks5 tcp")

	// 2. SOCKS5 UDP ASSOCIATE
	c2, err := net.Dial("tcp", srv)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()

	_, _ = c2.Write([]byte{5, 1, 2})
	_, _ = io.ReadFull(c2, r)
	_, _ = c2.Write([]byte{1, 4, 'u', 's', 'e', 'r', 4, 'p', 'a', 's', 's'})
	_, _ = io.ReadFull(c2, r)

	_, _ = c2.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	uRep := make([]byte, 10)
	_, _ = io.ReadFull(c2, uRep)
	if uRep[1] != 0 {
		t.Fatalf("socks5 udp associate failed: %v", uRep)
	}
	bndIP := net.IP(uRep[4:8]).String()
	bndPort := int(binary.BigEndian.Uint16(uRep[8:10]))

	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer clientUDP.Close()

	srvUDPAddr, _ := net.ResolveUDPAddr("udp", hostPort(bndIP, bndPort))
	udpPayload := []byte("hello socks5 udp")
	udpReqHeader := append([]byte{0, 0, 0}, addrBytes(t, echoUDP)...)
	packet := append(udpReqHeader, udpPayload...)
	_, _ = clientUDP.WriteToUDP(packet, srvUDPAddr)

	respBuf := make([]byte, 2048)
	_ = clientUDP.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := clientUDP.ReadFromUDP(respBuf)
	if err != nil {
		t.Fatalf("socks5 udp echo recv failed: %v", err)
	}
	if n < 10 {
		t.Fatalf("socks5 udp packet too short: %d", n)
	}
	gotData := string(respBuf[10:n])
	if gotData != string(udpPayload) {
		t.Fatalf("socks5 udp payload mismatch: got %q, want %q", gotData, udpPayload)
	}
}

func TestVLESS(t *testing.T) {
	echoTCP := startEchoTCP(t)
	lim := testLimits()
	out := newOut(t)
	udpMgr := NewUDPManager(out, 5*time.Second)
	t.Cleanup(func() { udpMgr.Close() })

	testUUID := "a5e18239-6523-446f-b258-2e06180632a7"
	lc := ListenerConfig{
		Type:      "vless",
		Passwords: []string{testUUID},
	}
	vh, err := newVLESSHandler(lc, out, NewGuard(lim), lim, udpMgr)
	if err != nil {
		t.Fatal(err)
	}
	srv := startServer(t, vh.handle, lim)

	c, err := net.Dial("tcp", srv)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	uBytes, _ := parseUUID(testUUID)
	h, p, _ := net.SplitHostPort(echoTCP)
	var pn int
	for _, ch := range p {
		pn = pn*10 + int(ch-'0')
	}
	var portB [2]byte
	binary.BigEndian.PutUint16(portB[:], uint16(pn))

	req := []byte{0x00}
	req = append(req, uBytes[:]...)
	req = append(req, 0x00) // addon length 0
	req = append(req, 0x01) // cmd tcp
	req = append(req, portB[:]...)
	req = append(req, 0x01) // atyp ipv4
	req = append(req, net.ParseIP(h).To4()...)

	_, _ = c.Write(req)

	resp := make([]byte, 2)
	_, _ = io.ReadFull(c, resp)
	if resp[0] != 0 || resp[1] != 0 {
		t.Fatalf("vless server resp error: %v", resp)
	}

	expectEcho(t, c, "hello vless")
}

func TestWebSocketUpgrade(t *testing.T) {
	echoTCP := startEchoTCP(t)
	lim := testLimits()
	out := newOut(t)

	// 后端为 VLESS 处理
	testUUID := "a5e18239-6523-446f-b258-2e06180632a7"
	vh, _ := newVLESSHandler(ListenerConfig{Passwords: []string{testUUID}}, out, NewGuard(lim), lim, nil)

	// WebSocket 传输层包装
	wsCfg := &WSConfig{Path: "/vless-ws"}
	handler := func(ctx context.Context, c net.Conn) {
		br := bufio.NewReaderSize(c, 8192)
		wsC, err := UpgradeWebSocket(c, br, wsCfg)
		if err != nil {
			return
		}
		vh.handle(ctx, wsC)
	}

	srv := startServer(t, handler, lim)

	c, err := net.Dial("tcp", srv)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// 1. 发起 HTTP WebSocket 握手
	req := "GET /vless-ws HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	_, _ = c.Write([]byte(req))

	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 101 {
		t.Fatalf("ws upgrade failed: %v, status=%d", err, resp.StatusCode)
	}

	// 2. 在 WebSocket 连接中传输 VLESS 请求帧（必须使用客户端掩码传输）
	uBytes, _ := parseUUID(testUUID)
	h, p, _ := net.SplitHostPort(echoTCP)
	var pn int
	for _, ch := range p {
		pn = pn*10 + int(ch-'0')
	}
	var portB [2]byte
	binary.BigEndian.PutUint16(portB[:], uint16(pn))

	vlessReq := []byte{0x00}
	vlessReq = append(vlessReq, uBytes[:]...)
	vlessReq = append(vlessReq, 0x00, 0x01)
	vlessReq = append(vlessReq, portB[:]...)
	vlessReq = append(vlessReq, 0x01)
	vlessReq = append(vlessReq, net.ParseIP(h).To4()...)

	// 构造带掩码的 WebSocket 客户端二进制帧
	mask := [4]byte{0x12, 0x34, 0x56, 0x78}
	maskedPayload := make([]byte, len(vlessReq))
	for i := range vlessReq {
		maskedPayload[i] = vlessReq[i] ^ mask[i%4]
	}
	frameHdr := []byte{0x82, 0x80 | byte(len(vlessReq))}
	frameHdr = append(frameHdr, mask[:]...)
	_, _ = c.Write(append(frameHdr, maskedPayload...))

	// 读取服务端返回的 WebSocket 二进制帧
	var wsHdr [2]byte
	_, _ = io.ReadFull(br, wsHdr[:])
	if wsHdr[0] != 0x82 {
		t.Fatalf("expected binary frame 0x82, got 0x%02x", wsHdr[0])
	}
	plen := int(wsHdr[1] & 0x7F)
	respPayload := make([]byte, plen)
	_, _ = io.ReadFull(br, respPayload)
	if len(respPayload) < 2 || respPayload[0] != 0 || respPayload[1] != 0 {
		t.Fatalf("vless over ws resp error: %v", respPayload)
	}
}

func TestConfigUDPDisable(t *testing.T) {
	disable := false
	cfg := &Config{
		Listeners: []ListenerConfig{
			{Type: "vless", Listen: "127.0.0.1:443", UDP: &disable},
			{Type: "shadowsocks", Listen: "127.0.0.1:8388"},
		},
	}
	setDefaults(cfg)

	if cfg.Listeners[0].IsUDP() != false {
		t.Fatal("expected listeners[0].IsUDP() to be false, got true")
	}
	if cfg.Listeners[1].IsUDP() != true {
		t.Fatal("expected listeners[1].IsUDP() to be true (default)")
	}
}

func TestWSSLayered(t *testing.T) {
	echoTCP := startEchoTCP(t)
	lim := testLimits()
	out := newOut(t)
	certFile, keyFile := selfSigned(t)

	testUUID := "a5e18239-6523-446f-b258-2e06180632a7"
	vh, _ := newVLESSHandler(ListenerConfig{Passwords: []string{testUUID}}, out, NewGuard(lim), lim, nil)

	wsCfg := &WSConfig{Path: "/wss-path"}
	cl, _ := newCertLoader(certFile, keyFile)
	tlsCfg := &tls.Config{
		GetCertificate: cl.get,
		NextProtos:     []string{"http/1.1"},
	}

	// 模拟 main.go 的标准洋葱模型：TLS -> WS -> VLESS
	coreHandler := func(ctx context.Context, c net.Conn) {
		br := bufio.NewReaderSize(c, 8192)
		wsC, err := UpgradeWebSocket(c, br, wsCfg)
		if err != nil {
			return
		}
		vh.handle(ctx, wsC)
	}

	handler := func(ctx context.Context, c net.Conn) {
		tc := tls.Server(c, tlsCfg)
		if err := tc.Handshake(); err != nil {
			return
		}
		coreHandler(ctx, tc)
	}

	srv := startServer(t, handler, lim)

	// 客户端：Dial TLS -> 发起 WS 升级 -> 发送 VLESS 数据包
	tlsClient, err := tls.Dial("tcp", srv, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tlsClient.Close()

	req := "GET /wss-path HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	_, _ = tlsClient.Write([]byte(req))

	br := bufio.NewReader(tlsClient)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 101 {
		t.Fatalf("wss upgrade failed: %v, status=%d", err, resp.StatusCode)
	}

	uBytes, _ := parseUUID(testUUID)
	h, p, _ := net.SplitHostPort(echoTCP)
	var pn int
	for _, ch := range p {
		pn = pn*10 + int(ch-'0')
	}
	var portB [2]byte
	binary.BigEndian.PutUint16(portB[:], uint16(pn))

	vlessReq := []byte{0x00}
	vlessReq = append(vlessReq, uBytes[:]...)
	vlessReq = append(vlessReq, 0x00, 0x01)
	vlessReq = append(vlessReq, portB[:]...)
	vlessReq = append(vlessReq, 0x01)
	vlessReq = append(vlessReq, net.ParseIP(h).To4()...)

	mask := [4]byte{0x12, 0x34, 0x56, 0x78}
	maskedPayload := make([]byte, len(vlessReq))
	for i := range vlessReq {
		maskedPayload[i] = vlessReq[i] ^ mask[i%4]
	}
	frameHdr := []byte{0x82, 0x80 | byte(len(vlessReq))}
	frameHdr = append(frameHdr, mask[:]...)
	_, _ = tlsClient.Write(append(frameHdr, maskedPayload...))

	var wsHdr [2]byte
	_, _ = io.ReadFull(br, wsHdr[:])
	if wsHdr[0] != 0x82 {
		t.Fatalf("expected binary frame 0x82, got 0x%02x", wsHdr[0])
	}
	plen := int(wsHdr[1] & 0x7F)
	respPayload := make([]byte, plen)
	_, _ = io.ReadFull(br, respPayload)
	if len(respPayload) < 2 || respPayload[0] != 0 || respPayload[1] != 0 {
		t.Fatalf("vless over wss resp error: %v", respPayload)
	}
}

func TestRealityFallback(t *testing.T) {
	echoTCP := startEchoTCP(t)
	lim := testLimits()
	guard := NewGuard(lim)

	rh, err := newRealityHandler(&RealityConfig{
		Dest:     echoTCP,
		ShortIDs: []string{"abcd"},
	}, func(ctx context.Context, c net.Conn) {
		t.Fatal("should not reach inner handler for probe traffic")
	}, guard, lim, nil)
	if err != nil {
		t.Fatal(err)
	}

	srv := startServer(t, rh.handle, lim)

	c, err := net.Dial("tcp", srv)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// 模拟非合规探测流量（普通 HTTP 请求或未带 ShortID 的 ClientHello）
	_, _ = c.Write([]byte("GET /probe HTTP/1.1\r\nHost: test\r\n\r\n"))
	buf := make([]byte, 128)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(buf[:n]), "GET /probe") {
		t.Fatalf("expected fallback echo to return probe data, got: %q", buf[:n])
	}
}

func TestX25519Keygen(t *testing.T) {
	priv, pub, err := GenerateX25519Keypair()
	if err != nil {
		t.Fatalf("GenerateX25519Keypair err: %v", err)
	}
	if len(priv) < 40 || len(pub) < 40 {
		t.Fatalf("unexpected key length: priv=%s, pub=%s", priv, pub)
	}
	sid := GenerateShortID()
	if len(sid) != 16 {
		t.Fatalf("unexpected shortID length: %s", sid)
	}
}

func TestEmbeddedFallback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addr := "127.0.0.1:0"
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	actualAddr := ln.Addr().String()
	_ = ln.Close()

	if err := StartEmbeddedFallback(ctx, actualAddr); err != nil {
		t.Fatalf("StartEmbeddedFallback err: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	c, err := net.Dial("tcp", actualAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// 模拟带 PROXY protocol v1 的请求
	req := "PROXY TCP4 1.2.3.4 5.6.7.8 12345 80\r\nGET / HTTP/1.1\r\nHost: test.com\r\nConnection: close\r\n\r\n"
	if _, err := c.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}

	resp, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(resp), "200 OK") || !strings.Contains(string(resp), "Edge Node Gateway") {
		t.Fatalf("unexpected fallback response: %s", string(resp))
	}
}

func TestVLESSFragmentedWSSUpgrade(t *testing.T) {
	echoTCP := startEchoTCP(t)
	lim := testLimits()
	out := newOut(t)
	certFile, keyFile := selfSigned(t)

	fbLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fbAddr := fbLn.Addr().String()
	_ = fbLn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = StartEmbeddedFallback(ctx, fbAddr)

	testUUID := "a5e18239-6523-446f-b258-2e06180632a7"
	vh, err := newVLESSHandler(ListenerConfig{
		Passwords: []string{testUUID},
		Fallback:  fbAddr,
	}, out, NewGuard(lim), lim, nil)
	if err != nil {
		t.Fatal(err)
	}

	cl, _ := newCertLoader(certFile, keyFile)
	tlsCfg := &tls.Config{
		GetCertificate: cl.get,
		NextProtos:     []string{"http/1.1"},
	}
	srv := startServer(t, func(ctx context.Context, c net.Conn) {
		tc := tls.Server(c, tlsCfg)
		if err := tc.Handshake(); err != nil {
			return
		}
		vh.handle(ctx, tc)
	}, lim)

	tlsClient, err := tls.Dial("tcp", srv, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tlsClient.Close()

	// 构造 VLESS 头 + 1800B 大首包模拟 TLS 1.3 Post-Quantum ClientHello (?ed=2048)
	uBytes, _ := parseUUID(testUUID)
	h, p, _ := net.SplitHostPort(echoTCP)
	var pn int
	for _, ch := range p {
		pn = pn*10 + int(ch-'0')
	}
	var portB [2]byte
	binary.BigEndian.PutUint16(portB[:], uint16(pn))

	bigMsg := strings.Repeat("Q", 1600)
	vlessEarly := []byte{0x00}
	vlessEarly = append(vlessEarly, uBytes[:]...)
	vlessEarly = append(vlessEarly, 0x00, 0x01, portB[0], portB[1], 0x01)
	vlessEarly = append(vlessEarly, net.ParseIP(h).To4()...)
	vlessEarly = append(vlessEarly, []byte(bigMsg)...)

	b64ED := base64.RawURLEncoding.EncodeToString(vlessEarly)
	fullReq := "GET /vless-ws HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		"Sec-WebSocket-Protocol: " + b64ED + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"

	// 故意拆成 3 个独立 TLS Record 发送，模拟真实跨包分片场景
	_, _ = tlsClient.Write([]byte(fullReq[:512]))
	time.Sleep(10 * time.Millisecond)
	_, _ = tlsClient.Write([]byte(fullReq[512:1500]))
	time.Sleep(10 * time.Millisecond)
	_, _ = tlsClient.Write([]byte(fullReq[1500:]))

	br := bufio.NewReader(tlsClient)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 101 {
		t.Fatalf("fragmented wss upgrade failed: err=%v, status=%v", err, resp)
	}

	// 读取服务端返回的 WebSocket 帧（包含 [0x00, 0x00] VLESS 头 + bigMsg 回显）
	var got []byte
	for len(got) < 2+len(bigMsg) {
		var hdr [2]byte
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			t.Fatalf("read ws frame hdr: %v", err)
		}
		plen := int(hdr[1] & 0x7F)
		if plen == 126 {
			var s [2]byte
			_, _ = io.ReadFull(br, s[:])
			plen = int(binary.BigEndian.Uint16(s[:]))
		}
		chunk := make([]byte, plen)
		if _, err := io.ReadFull(br, chunk); err != nil {
			t.Fatalf("read ws frame body: %v", err)
		}
		got = append(got, chunk...)
	}
	if string(got[2:]) != bigMsg {
		t.Fatalf("early data echo mismatch: len=%d", len(got))
	}
}

func TestVLESSXUDP(t *testing.T) {
	_, echoUDP := startEchoUDP(t)
	lim := testLimits()
	out := newOut(t)
	udpMgr := NewUDPManager(out, 5*time.Second)
	t.Cleanup(func() { udpMgr.Close() })

	testUUID := "a5e18239-6523-446f-b258-2e06180632a7"
	vh, err := newVLESSHandler(ListenerConfig{Passwords: []string{testUUID}}, out, NewGuard(lim), lim, udpMgr)
	if err != nil {
		t.Fatal(err)
	}
	srv := startServer(t, vh.handle, lim)

	c, err := net.Dial("tcp", srv)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	uBytes, _ := parseUUID(testUUID)
	h, p, _ := net.SplitHostPort(echoUDP)
	var pn int
	for _, ch := range p {
		pn = pn*10 + int(ch-'0')
	}

	// VLESS XUDP 头: [0x00] [UUID 16B] [AddonLen 0x00] [Cmd 0x03]
	vlessHdr := append([]byte{0x00}, uBytes[:]...)
	vlessHdr = append(vlessHdr, 0x00, 0x03)

	// XUDP New Frame: [MetaLen 2B] [SessID=1(2B), Status=0x01(New), Opt=0x01(Data), Net=0x02(UDP), Port(2B), ATYP=1, IPv4(4B), GlobalID(8B)] [PayloadLen 2B] [Payload]
	meta := []byte{0x00, 0x01, 0x01, 0x01, 0x02}
	meta = appendVLESSAddr(meta, h, pn)
	meta = append(meta, make([]byte, 8)...) // 8-byte GlobalID
	msg := []byte("hello xudp dns")

	var pkt bytes.Buffer
	pkt.Write(vlessHdr)
	_ = binary.Write(&pkt, binary.BigEndian, uint16(len(meta)))
	pkt.Write(meta)
	_ = binary.Write(&pkt, binary.BigEndian, uint16(len(msg)))
	pkt.Write(msg)

	if _, err := c.Write(pkt.Bytes()); err != nil {
		t.Fatal(err)
	}

	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	var vResp [2]byte
	if _, err := io.ReadFull(c, vResp[:]); err != nil || vResp != [2]byte{0, 0} {
		t.Fatalf("xudp vless resp err: %v, %v", err, vResp)
	}

	var rMetaLen uint16
	if err := binary.Read(c, binary.BigEndian, &rMetaLen); err != nil {
		t.Fatalf("read xudp resp meta len: %v", err)
	}
	rMeta := make([]byte, rMetaLen)
	if _, err := io.ReadFull(c, rMeta); err != nil {
		t.Fatal(err)
	}
	var rPayLen uint16
	if err := binary.Read(c, binary.BigEndian, &rPayLen); err != nil {
		t.Fatal(err)
	}
	rPay := make([]byte, rPayLen)
	if _, err := io.ReadFull(c, rPay); err != nil {
		t.Fatal(err)
	}
	if string(rPay) != string(msg) {
		t.Fatalf("xudp payload mismatch: got %q, want %q", rPay, msg)
	}
}

func TestHy2UDPCodecAndQPACKAuth(t *testing.T) {
	// 1. 验证 Hysteria 2 官方 UDP 分片与重组编解码
	bigPayload := bytes.Repeat([]byte("HY2UDP!"), 400) // 2800B > 1100B
	frames := encodeHy2UDPFrames(42, 7, "8.8.8.8:53", bigPayload, 1100)
	if len(frames) < 3 {
		t.Fatalf("expected >=3 fragments, got %d", len(frames))
	}
	var reassembled []byte
	for i, f := range frames {
		sID, pID, fID, fCnt, addr, data, ok := parseHy2UDP(f)
		if !ok || sID != 42 || pID != 7 || int(fID) != i || int(fCnt) != len(frames) || addr != "8.8.8.8:53" {
			t.Fatalf("parseHy2UDP mismatch on frag %d: ok=%v sID=%d pID=%d fID=%d/%d addr=%q", i, ok, sID, pID, fID, fCnt, addr)
		}
		reassembled = append(reassembled, data...)
	}
	if !bytes.Equal(reassembled, bigPayload) {
		t.Fatal("reassembled hy2 udp payload mismatch")
	}

	// 2. 验证带 GREASE 帧 + RFC 7541 Huffman 编码的 QPACK /auth 解码
	// GREASE frame: type=0x21 (33), len=3, payload="abc"
	// HEADERS frame: type=0x01, QPACK:
	//   0x00, 0x00 (Prefix)
	//   0xd4 (:method = POST, static 20)
	//   0x51, 0x84, 0x60, 0x76, 0xa6, 0x7f (:path = "/auth" Huffman)
	//   0x2f, 0x02, 0x9f, 0xd2, 0x12, 0x5b, 0x0c, 0x35, 0x87, 0x6a, 0x67 (Name "hysteria-auth" Huffman 9B: 0x20|0x08|0x07=0x2f, +2=9)
	//   0x8e, 0x3e, 0x2f, 0xcf, 0xdd, 0x9d, 0x7a, 0x61, 0xc7, 0xcf, 0xc4, 0xd8, 0xb8, 0x79, 0xf7 (Val "oGXZQkjFHYwgGUxz" Huffman 14B: 0x80|14=0x8e)
	qpackBlock := []byte{
		0x00, 0x00,
		0xd4,
		0x51, 0x84, 0x60, 0x76, 0xa6, 0x7f,
		0x2f, 0x02, 0x9f, 0xd2, 0x12, 0x5b, 0x0c, 0x35, 0x87, 0x6a, 0x67,
		0x8e, 0x3e, 0x2f, 0xcf, 0xdd, 0x9d, 0x7a, 0x61, 0xc7, 0xcf, 0xc4, 0xd8, 0xb8, 0x79, 0xf7,
	}
	streamBytes := []byte{0x21, 0x03, 'a', 'b', 'c', 0x01, byte(len(qpackBlock))}
	streamBytes = append(streamBytes, qpackBlock...)

	hdrs, err := readH3Headers(bufio.NewReader(bytes.NewReader(streamBytes)))
	if err != nil {
		t.Fatalf("readH3Headers failed: %v", err)
	}
	if hdrs[":method"] != "POST" || hdrs[":path"] != "/auth" || hdrs["hysteria-auth"] != "oGXZQkjFHYwgGUxz" {
		t.Fatalf("decoded headers mismatch: %+v", hdrs)
	}

	// 3. 验证服务端 233 认证成功响应帧编解码回环
	respFrame := buildHy2AuthResponseFrame(true, 0)
	respHdrs, err := readH3Headers(bufio.NewReader(bytes.NewReader(respFrame)))
	if err != nil {
		t.Fatalf("readH3Headers on auth response failed: %v", err)
	}
	if respHdrs[":status"] != "233" || respHdrs["hysteria-udp"] != "true" || respHdrs["hysteria-cc-rx"] != "0" {
		t.Fatalf("auth response headers mismatch: %+v", respHdrs)
	}
}

func TestShadowsocksTCPAndUDP(t *testing.T) {
	echoTCP := startEchoTCP(t)
	echoUDP := startEchoUDP(t)
	lim := testLimits()
	out := newOut(t)
	udpMgr := NewUDPManager(out, 5*time.Second)
	t.Cleanup(func() { udpMgr.Close() })

	lc := ListenerConfig{
		Type:     "shadowsocks",
		Method:   "aes-256-gcm",
		Password: "test-ss-password-2026",
	}
	sh := newSSHandler(lc, out, NewGuard(lim), lim, udpMgr)
	srv := startServer(t, sh.handle, lim)

	// 1. Shadowsocks TCP AEAD
	rawTCP, err := net.Dial("tcp", srv)
	if err != nil {
		t.Fatal(err)
	}
	defer rawTCP.Close()
	clientSS := newSSConn(rawTCP, sh.key, newReplayFilter(1024))
	if _, err := clientSS.Write(addrBytes(t, echoTCP)); err != nil {
		t.Fatal(err)
	}
	expectEcho(t, clientSS, "hello shadowsocks aead tcp")

	// 2. Shadowsocks UDP AEAD (验证无内存重叠 panic 且双向加解密正常)
	uLn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = uLn.Close()
	})
	go sh.ServeUDP(ctx, uLn)

	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer clientUDP.Close()

	salt := make([]byte, len(sh.key))
	_, _ = rand.Read(salt)
	aead := newGCM(sh.key, salt)
	var nonce [12]byte
	msg := []byte("hello shadowsocks aead udp")
	plain := append(addrBytes(t, echoUDP), msg...)
	pkt := aead.Seal(salt, nonce[:], plain, nil)

	if _, err := clientUDP.WriteToUDP(pkt, uLn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}

	rbuf := make([]byte, 2048)
	_ = clientUDP.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := clientUDP.ReadFromUDP(rbuf)
	if err != nil {
		t.Fatalf("ss udp recv failed: %v", err)
	}
	respSalt := rbuf[:len(sh.key)]
	respAead := newGCM(sh.key, respSalt)
	var respNonce [12]byte
	dec, err := respAead.Open(nil, respNonce[:], rbuf[len(sh.key):n], nil)
	if err != nil {
		t.Fatalf("ss udp decrypt failed: %v", err)
	}
	_, _, off, err := parseAddrBytes(dec)
	if err != nil {
		t.Fatalf("ss udp parseAddrBytes failed: %v", err)
	}
	if string(dec[off:]) != string(msg) {
		t.Fatalf("ss udp payload mismatch: got %q, want %q", dec[off:], msg)
	}
}

func TestGuardAuthSuccessNoSelfBan(t *testing.T) {
	lim := testLimits()
	lim.BanAfterFailures = 3
	g := NewGuard(lim)
	defer g.Close()

	userIP := netip.MustParseAddr("203.0.113.10")
	attackerIP := netip.MustParseAddr("198.51.100.99")

	// 正常用户完成一次认证后即使偶发多次异常断开也绝不会被封禁
	g.AuthSuccess(userIP)
	for i := 0; i < 10; i++ {
		g.Fail(userIP)
	}
	if !g.Acquire(userIP) {
		t.Fatal("authenticated user IP should never be banned by Guard")
	}
	g.Release(userIP)

	// 未认证扫描器连续口令错误达到阈值后被正常封禁
	for i := 0; i < 3; i++ {
		g.Fail(attackerIP)
	}
	if g.Acquire(attackerIP) {
		t.Fatal("unauthenticated attacker IP should be banned after 3 failures")
	}
}
