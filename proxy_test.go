package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
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
