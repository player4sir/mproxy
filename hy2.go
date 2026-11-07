package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mproxy/internal/hy2cc"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/quicvarint"
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
	maxTx      uint64
	maxRx      uint64
	out        *Outbound
	guard      *Guard
	lim        Limits
	udpMgr     *UDPManager
}

func newHy2Handler(lc ListenerConfig, out *Outbound, g *Guard, lim Limits, udpMgr *UDPManager) *hy2Handler {
	pw := lc.Password
	masq := ""
	var maxTx, maxRx uint64
	if lc.Hy2 != nil {
		if lc.Hy2.Password != "" {
			pw = lc.Hy2.Password
		}
		masq = lc.Hy2.Masquerade
		if lc.Hy2.DownMbps > 0 {
			maxTx = uint64(lc.Hy2.DownMbps) * 125000
		}
		if lc.Hy2.UpMbps > 0 {
			maxRx = uint64(lc.Hy2.UpMbps) * 125000
		}
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
		maxTx:      maxTx,
		maxRx:      maxRx,
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

	// 关键优化：
	// 1. DisablePathMTUDiscovery: true 彻底杜绝 PPPoE / TUN / 跨网运营商丢弃 1452B 大包探测帧引发的拥塞窗口雪崩
	// 2. MaxIncomingStreams: 4096 消除浏览器高并发打开多标签页时的流排队阻塞
	quicCfg := &quic.Config{
		EnableDatagrams:                true,
		DisablePathMTUDiscovery:        true,
		MaxIncomingStreams:             4096,
		MaxIncomingUniStreams:          1024,
		MaxIdleTimeout:                 lim.IdleTimeout.Duration,
		KeepAlivePeriod:                15 * time.Second,
		InitialStreamReceiveWindow:     8 * 1024 * 1024,
		InitialConnectionReceiveWindow: 32 * 1024 * 1024,
		MaxStreamReceiveWindow:         16 * 1024 * 1024,
		MaxConnectionReceiveWindow:     64 * 1024 * 1024,
		Allow0RTT:                      true,
	}

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
				h.handleSession(ctx, sess, ip)
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

// quicStreamConn 将 quic.Stream 包装为完整的 net.Conn 接口
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

func (c *quicStreamConn) Close() error {
	c.Stream.CancelRead(0)
	return c.Stream.Close()
}

// handleSession 处理官方标准 Hysteria 2 协议会话
func (h *hy2Handler) handleSession(ctx context.Context, sess quic.Connection, clientIP netip.Addr) {
	defer sess.CloseWithError(0x00, "session closed")

	// 0. 发送 HTTP/3 Control Stream 与 SETTINGS 帧 (RFC 9114 规范要求，Dynamic Table = 0)
	go func() {
		if uni, err := sess.OpenUniStream(); err == nil {
			_, _ = uni.Write([]byte{0x00, 0x04, 0x00})
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

	// 1. 等待首条双向流完成 HTTP/3 POST /auth 握手
	authStream, err := sess.AcceptStream(ctx)
	if err != nil {
		return
	}
	_ = authStream.SetDeadline(time.Now().Add(h.lim.HandshakeTimeout.Duration))

	authBR := acquireReader(authStream)
	hdrs, h3Err := readH3Headers(authBR)
	releaseReader(authBR)
	if h3Err != nil {
		_ = authStream.Close()
		authStream.CancelRead(0)
		return
	}

	go func() {
		_, _ = io.Copy(io.Discard, authStream)
	}()

	authenticated := false
	gotAuth, hasAuth := hdrs["hysteria-auth"]
	gotPath := hdrs[":path"]

	if len(h.password) == 0 {
		authenticated = true
	} else if hasAuth && subtle.ConstantTimeCompare([]byte(gotAuth), []byte(h.password)) == 1 && (gotPath == "" || gotPath == "/auth") {
		authenticated = true
	}

	if !authenticated {
		// 仅当客户端显式携带了错误的 Hysteria-Auth 口令时才记为暴力破解失败；普通浏览器访问返回 HTTP/3 200 OK 伪装页
		if hasAuth {
			h.guard.Fail(clientIP)
		}
		writeH3Masquerade(authStream)
		_ = authStream.Close()
		return
	}

	h.guard.AuthSuccess(clientIP)
	_ = authStream.SetDeadline(time.Time{})

	// 注入官方 Hysteria 2 拥塞控制引擎：客户端指定下行带宽时启用 Brutal 恒定速率抗丢包，未指定时启用 BBR 拥塞控制（取代标准 quic-go 在跨境丢包链路上降窗失速的 Reno/CUBIC）
	clientRx, _ := strconv.ParseUint(hdrs["hysteria-cc-rx"], 10, 64)
	actualTx := clientRx
	if h.maxTx > 0 && actualTx > h.maxTx {
		actualTx = h.maxTx
	}
	if actualTx > 0 {
		hy2cc.UseBrutal(sess, actualTx)
	} else {
		hy2cc.UseBBR(sess)
	}

	respFrame := buildHy2AuthResponseFrame(h.udpMgr != nil, h.maxRx)
	if _, err := authStream.Write(respFrame); err != nil {
		_ = authStream.Close()
		return
	}
	_ = authStream.Close()

	// 2. 启动符合官方 Hysteria 2 规范的 QUIC Datagram UDP 中继（含分片与重组）
	sessCtx, cancelSess := context.WithCancel(ctx)
	defer cancelSess()
	go h.handleDatagrams(sessCtx, sess)

	// 3. 循环接收客户端的 TCP 代理请求流 (0x401)
	for {
		stream, err := sess.AcceptStream(ctx)
		if err != nil {
			return
		}
		go h.handleTCPStream(sessCtx, sess, stream)
	}
}

// buildHy2AuthResponseFrame 构造官方 Hysteria 2 认证成功 HTTP/3 HEADERS 帧 (:status=233, hysteria-udp, hysteria-cc-rx)
func buildHy2AuthResponseFrame(udpEnabled bool, maxRx uint64) []byte {
	udpVal := "false"
	if udpEnabled {
		udpVal = "true"
	}
	rxVal := strconv.FormatUint(maxRx, 10)

	qpackPayload := make([]byte, 0, 64)
	qpackPayload = append(qpackPayload,
		0x00, 0x00, // QPACK Prefix: Required Insert Count = 0, Base = 0
		0x5f, 0x30, 0x03, '2', '3', '3', // :status = 233 (Static Table 63 = 15 + 48)
		0x27, 0x05, 'h', 'y', 's', 't', 'e', 'r', 'i', 'a', '-', 'u', 'd', 'p', byte(len(udpVal)),
	)
	qpackPayload = append(qpackPayload, udpVal...)
	qpackPayload = append(qpackPayload,
		0x27, 0x07, 'h', 'y', 's', 't', 'e', 'r', 'i', 'a', '-', 'c', 'c', '-', 'r', 'x', byte(len(rxVal)),
	)
	qpackPayload = append(qpackPayload, rxVal...)

	frame := make([]byte, 0, 4+len(qpackPayload))
	frame = append(frame, 0x01) // HTTP/3 Frame Type: HEADERS
	frame = quicvarint.Append(frame, uint64(len(qpackPayload)))
	frame = append(frame, qpackPayload...)
	return frame
}

// writeH3Masquerade 向主动探测者或普通 HTTP/3 浏览器返回标准的 200 OK HTML 响应帧
func writeH3Masquerade(w io.Writer) {
	qpackHdr := []byte{
		0x00, 0x00, // QPACK Prefix
		0xd9, // Indexed Static Table 25 -> :status = 200
		0xf4, // Indexed Static Table 52 -> content-type = text/html; charset=utf-8
	}
	body := []byte(embeddedHTML)
	var buf bytes.Buffer
	buf.WriteByte(0x01) // Frame: HEADERS
	buf = *bytes.NewBuffer(quicvarint.Append(buf.Bytes(), uint64(len(qpackHdr))))
	buf.Write(qpackHdr)
	buf.WriteByte(0x00) // Frame: DATA
	raw := quicvarint.Append(buf.Bytes(), uint64(len(body)))
	raw = append(raw, body...)
	_, _ = w.Write(raw)
}

// handleTCPStream 处理 Hysteria 2 标准 TCPRequest (0x401 报头)，统一使用带缓冲流避免首包字节丢失
func (h *hy2Handler) handleTCPStream(ctx context.Context, sess quic.Connection, stream quic.Stream) {
	sc := &quicStreamConn{Stream: stream, sess: sess}
	defer sc.Close()

	_ = stream.SetReadDeadline(time.Now().Add(h.lim.HandshakeTimeout.Duration))
	br := acquireReader(stream)
	defer releaseReader(br)

	reqID, err := quicvarint.Read(br)
	if err != nil {
		return
	}

	var targetHost string
	var targetPort int
	isHy2Req := false

	if reqID == 0x401 {
		isHy2Req = true
		addrLen, err := quicvarint.Read(br)
		if err != nil || addrLen == 0 || addrLen > 2048 {
			return
		}
		addrBuf := make([]byte, addrLen)
		if _, err := io.ReadFull(br, addrBuf); err != nil {
			return
		}

		padLen, err := quicvarint.Read(br)
		if err != nil || padLen > 65536 {
			return
		}
		if padLen > 0 {
			if _, err := io.CopyN(io.Discard, br, int64(padLen)); err != nil {
				return
			}
		}

		addrStr := string(addrBuf)
		if host, pStr, err := net.SplitHostPort(addrStr); err == nil {
			targetHost = host
			targetPort, _ = strconv.Atoi(pStr)
		} else {
			targetHost = addrStr
			targetPort = 80
		}
	} else {
		return
	}

	if targetPort <= 0 || targetPort > 65535 {
		return
	}

	_ = stream.SetReadDeadline(time.Time{})

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
		// 发送 Hysteria 2 官方 TCPResponse: [Status=0x00(OK), MsgLen=0x00, PadLen=0x00]
		if _, err := stream.Write([]byte{0x00, 0x00, 0x00}); err != nil {
			return
		}
	}

	relay(&bufConn{Conn: sc, r: br}, up, h.lim.IdleTimeout.Duration)
}

// ---------- Hysteria 2 官方 UDP Datagram 编解码与分片重组 ----------
// 官方报文格式: [SessionID 4B] [PacketID 2B] [FragID 1B] [FragCount 1B] [quicvarint AddrLen] [Addr "host:port"] [Payload]

type hy2DefragKey struct {
	sessID uint32
	pktID  uint16
}

type hy2DefragItem struct {
	addr     string
	chunks   [][]byte
	received int
	created  time.Time
}

func parseHy2UDP(msg []byte) (sessID uint32, pktID uint16, fragID, fragCount uint8, addr string, data []byte, ok bool) {
	if len(msg) < 9 {
		return 0, 0, 0, 0, "", nil, false
	}
	sessID = binary.BigEndian.Uint32(msg[0:4])
	pktID = binary.BigEndian.Uint16(msg[4:6])
	fragID = msg[6]
	fragCount = msg[7]
	if fragCount == 0 || fragID >= fragCount {
		return 0, 0, 0, 0, "", nil, false
	}
	r := bytes.NewReader(msg[8:])
	addrLen, err := quicvarint.Read(r)
	if err != nil || addrLen == 0 || addrLen > 2048 || addrLen > uint64(r.Len()) {
		return 0, 0, 0, 0, "", nil, false
	}
	varintLen := len(msg[8:]) - r.Len()
	addrStart := 8 + varintLen
	addrEnd := addrStart + int(addrLen)
	if addrEnd > len(msg) {
		return 0, 0, 0, 0, "", nil, false
	}
	addr = string(msg[addrStart:addrEnd])
	data = msg[addrEnd:]
	return sessID, pktID, fragID, fragCount, addr, data, true
}

func encodeHy2UDPFrames(sessID uint32, pktID uint16, addr string, payload []byte, maxSize int) [][]byte {
	addrBytes := []byte(addr)
	varintLen := int(quicvarint.Len(uint64(len(addrBytes))))
	hdrLen := 8 + varintLen + len(addrBytes)
	maxChunk := maxSize - hdrLen
	if maxChunk < 128 {
		maxChunk = 512
	}

	buildOne := func(fID, fCount uint8, chunk []byte) []byte {
		pkt := make([]byte, 8, hdrLen+len(chunk))
		binary.BigEndian.PutUint32(pkt[0:4], sessID)
		binary.BigEndian.PutUint16(pkt[4:6], pktID)
		pkt[6] = fID
		pkt[7] = fCount
		pkt = quicvarint.Append(pkt, uint64(len(addrBytes)))
		pkt = append(pkt, addrBytes...)
		pkt = append(pkt, chunk...)
		return pkt
	}

	if len(payload) <= maxChunk {
		return [][]byte{buildOne(0, 1, payload)}
	}

	totalFrags := (len(payload) + maxChunk - 1) / maxChunk
	if totalFrags > 255 {
		return nil
	}
	frames := make([][]byte, 0, totalFrags)
	for i := 0; i < totalFrags; i++ {
		start := i * maxChunk
		end := start + maxChunk
		if end > len(payload) {
			end = len(payload)
		}
		frames = append(frames, buildOne(uint8(i), uint8(totalFrags), payload[start:end]))
	}
	return frames
}

func (h *hy2Handler) handleDatagrams(ctx context.Context, sess quic.Connection) {
	connSeq := udpSeq.Add(1)
	var pktSeq atomic.Uint32
	var maxDgramSize atomic.Int32
	maxDgramSize.Store(1120)

	var keysMu sync.Mutex
	activeKeys := make(map[string]struct{})
	defer func() {
		keysMu.Lock()
		keys := make([]string, 0, len(activeKeys))
		for k := range activeKeys {
			keys = append(keys, k)
		}
		keysMu.Unlock()
		for _, k := range keys {
			h.udpMgr.RemoveSession(k)
		}
	}()

	defrag := make(map[hy2DefragKey]*hy2DefragItem)

	sendToClient := func(sID uint32, respHost string, respPort int, respPayload []byte) error {
		pID := uint16(pktSeq.Add(1))
		respAddr := hostPort(respHost, respPort)
		curMax := int(maxDgramSize.Load())
		frames := encodeHy2UDPFrames(sID, pID, respAddr, respPayload, curMax)
		for _, f := range frames {
			if err := sess.SendDatagram(f); err != nil {
				var tooLarge *quic.DatagramTooLargeError
				if errors.As(err, &tooLarge) {
					newMax := 900
					if tooLarge.MaxDataLen > 64 {
						newMax = int(tooLarge.MaxDataLen)
					}
					maxDgramSize.Store(int32(newMax))
					retryFrames := encodeHy2UDPFrames(sID, uint16(pktSeq.Add(1)), respAddr, respPayload, newMax)
					for _, rf := range retryFrames {
						if rerr := sess.SendDatagram(rf); rerr != nil {
							return rerr
						}
					}
					return nil
				}
				return err
			}
		}
		return nil
	}

	for {
		msg, err := sess.ReceiveDatagram(ctx)
		if err != nil {
			return
		}

		sessID, pktID, fragID, fragCount, addrStr, payload, ok := parseHy2UDP(msg)
		if !ok {
			continue
		}

		if fragCount > 1 {
			now := time.Now()
			if len(defrag) > 64 {
				for k, v := range defrag {
					if now.Sub(v.created) > 5*time.Second {
						delete(defrag, k)
					}
				}
				if len(defrag) > 128 {
					clear(defrag)
				}
			}
			dk := hy2DefragKey{sessID: sessID, pktID: pktID}
			item, exists := defrag[dk]
			if !exists || len(item.chunks) != int(fragCount) {
				item = &hy2DefragItem{
					addr:    addrStr,
					chunks:  make([][]byte, fragCount),
					created: now,
				}
				defrag[dk] = item
			}
			if item.chunks[fragID] == nil {
				cp := make([]byte, len(payload))
				copy(cp, payload)
				item.chunks[fragID] = cp
				item.received++
			}
			if item.received < int(fragCount) {
				continue
			}
			payload = bytes.Join(item.chunks, nil)
			addrStr = item.addr
			delete(defrag, dk)
		}

		host, pStr, err := net.SplitHostPort(addrStr)
		if err != nil {
			continue
		}
		port, err := strconv.Atoi(pStr)
		if err != nil || port <= 0 || port > 65535 {
			continue
		}

		clientKey := fmt.Sprintf("hy2:%d:%d", connSeq, sessID)
		keysMu.Lock()
		activeKeys[clientKey] = struct{}{}
		keysMu.Unlock()

		sID := sessID
		_ = h.udpMgr.SendPacket(clientKey, host, port, payload, func(respHost string, respPort int, respPayload []byte) error {
			return sendToClient(sID, respHost, respPort, respPayload)
		})
	}
}

// ---------- 纯标准库 HTTP/3 帧读取与 RFC 9204 QPACK / RFC 7541 Huffman 解码器 ----------

func readH3Headers(br *bufio.Reader) (map[string]string, error) {
	for i := 0; i < 16; i++ {
		frameType, err := quicvarint.Read(br)
		if err != nil {
			return nil, err
		}
		frameLen, err := quicvarint.Read(br)
		if err != nil {
			return nil, err
		}
		if frameLen > 65536 {
			return nil, errors.New("h3 frame exceeds limit")
		}
		if frameType == 0x01 { // HEADERS Frame
			buf := make([]byte, frameLen)
			if _, err := io.ReadFull(br, buf); err != nil {
				return nil, err
			}
			return decodeQPACKHeaders(buf)
		}
		// 跳过 HTTP/3 GREASE 帧或其他扩展帧 (RFC 9114 §7.2.8)
		if _, err := io.CopyN(io.Discard, br, int64(frameLen)); err != nil {
			return nil, err
		}
	}
	return nil, errors.New("h3 headers frame not found")
}

func readQPACKInt(b []byte, idx int, prefixBits uint) (uint64, int, bool) {
	if idx >= len(b) {
		return 0, idx, false
	}
	mask := uint64((1 << prefixBits) - 1)
	val := uint64(b[idx]) & mask
	idx++
	if val < mask {
		return val, idx, true
	}
	var shift uint
	for idx < len(b) {
		c := b[idx]
		idx++
		val += uint64(c&0x7f) << shift
		if c&0x80 == 0 {
			return val, idx, true
		}
		shift += 7
		if shift > 56 {
			return 0, idx, false
		}
	}
	return 0, idx, false
}

func readQPACKStr(b []byte, idx int, prefixBits uint) (string, int, bool) {
	if idx >= len(b) {
		return "", idx, false
	}
	isHuff := (b[idx] & (1 << prefixBits)) != 0
	sLen, nextIdx, ok := readQPACKInt(b, idx, prefixBits)
	if !ok || sLen > 65536 || nextIdx+int(sLen) > len(b) {
		return "", idx, false
	}
	raw := b[nextIdx : nextIdx+int(sLen)]
	nextIdx += int(sLen)
	if !isHuff {
		return string(raw), nextIdx, true
	}
	s, err := huffmanDecode(raw)
	if err != nil {
		return "", idx, false
	}
	return s, nextIdx, true
}

func qpackStaticNameVal(idx int) (string, string) {
	switch idx {
	case 0:
		return ":authority", ""
	case 1:
		return ":path", "/"
	case 15:
		return ":method", "CONNECT"
	case 16:
		return ":method", "DELETE"
	case 17:
		return ":method", "GET"
	case 18:
		return ":method", "HEAD"
	case 19:
		return ":method", "OPTIONS"
	case 20:
		return ":method", "POST"
	case 21:
		return ":method", "PUT"
	case 22:
		return ":scheme", "http"
	case 23:
		return ":scheme", "https"
	case 24:
		return ":status", "103"
	case 25:
		return ":status", "200"
	case 26:
		return ":status", "304"
	case 27:
		return ":status", "404"
	case 28:
		return ":status", "503"
	case 63:
		return ":status", "100"
	case 64:
		return ":status", "204"
	case 65:
		return ":status", "206"
	case 66:
		return ":status", "302"
	case 67:
		return ":status", "400"
	case 68:
		return ":status", "403"
	case 69:
		return ":status", "421"
	case 70:
		return ":status", "425"
	case 71:
		return ":status", "500"
	default:
		return "", ""
	}
}

func decodeQPACKHeaders(b []byte) (map[string]string, error) {
	_, idx, ok := readQPACKInt(b, 0, 8) // Required Insert Count
	if !ok {
		return nil, errors.New("qpack: invalid ric")
	}
	_, idx, ok = readQPACKInt(b, idx, 7) // Delta Base
	if !ok {
		return nil, errors.New("qpack: invalid base")
	}

	hdrs := make(map[string]string, 8)
	for idx < len(b) {
		first := b[idx]
		switch {
		case first&0x80 != 0: // 1 T Index(6+): Indexed Field Line
			isStatic := (first & 0x40) != 0
			tIdx, nextIdx, ok := readQPACKInt(b, idx, 6)
			if !ok {
				return hdrs, nil
			}
			idx = nextIdx
			if isStatic {
				if k, v := qpackStaticNameVal(int(tIdx)); k != "" {
					hdrs[k] = v
				}
			}

		case first&0xC0 == 0x40: // 01 N T NameIndex(4+) + Value(7+)
			isStatic := (first & 0x10) != 0
			nIdx, nextIdx, ok := readQPACKInt(b, idx, 4)
			if !ok {
				return hdrs, nil
			}
			val, nextIdx2, ok := readQPACKStr(b, nextIdx, 7)
			if !ok {
				return hdrs, nil
			}
			idx = nextIdx2
			if isStatic {
				if k, _ := qpackStaticNameVal(int(nIdx)); k != "" {
					hdrs[k] = val
				}
			}

		case first&0xE0 == 0x20: // 001 N H NameLen(3+) + Name + H ValLen(7+) + Value
			name, nextIdx, ok := readQPACKStr(b, idx, 3)
			if !ok {
				return hdrs, nil
			}
			val, nextIdx2, ok := readQPACKStr(b, nextIdx, 7)
			if !ok {
				return hdrs, nil
			}
			idx = nextIdx2
			hdrs[strings.ToLower(name)] = val

		case first&0xF0 == 0x10: // 0001 Index(4+): Post-Base Indexed
			_, nextIdx, ok := readQPACKInt(b, idx, 4)
			if !ok {
				return hdrs, nil
			}
			idx = nextIdx

		default: // 0000 N Index(3+) + Value(7+): Post-Base Literal Name Ref
			_, nextIdx, ok := readQPACKInt(b, idx, 3)
			if !ok {
				return hdrs, nil
			}
			_, nextIdx2, ok := readQPACKStr(b, nextIdx, 7)
			if !ok {
				return hdrs, nil
			}
			idx = nextIdx2
		}
	}
	return hdrs, nil
}

type huffNode struct {
	children [2]*huffNode
	sym      byte
	isLeaf   bool
}

var (
	huffOnce sync.Once
	huffRoot *huffNode
)

// RFC 7541 Appendix B 标准 Huffman 编码表（256 符号，与 QPACK RFC 9204 完全一致）
var rfc7541HuffmanTable = [256]struct {
	code uint32
	bits uint8
}{
	{0x1ff8, 13}, {0x7fffd8, 23}, {0xfffffe2, 28}, {0xfffffe3, 28}, {0xfffffe4, 28}, {0xfffffe5, 28}, {0xfffffe6, 28}, {0xfffffe7, 28},
	{0xfffffe8, 28}, {0xffffea, 24}, {0x3ffffffc, 30}, {0xfffffe9, 28}, {0xfffffea, 28}, {0x3ffffffd, 30}, {0xfffffeb, 28}, {0xfffffec, 28},
	{0xfffffed, 28}, {0xfffffee, 28}, {0xfffffef, 28}, {0xffffff0, 28}, {0xffffff1, 28}, {0xffffff2, 28}, {0x3ffffffe, 30}, {0xffffff3, 28},
	{0xffffff4, 28}, {0xffffff5, 28}, {0xffffff6, 28}, {0xffffff7, 28}, {0xffffff8, 28}, {0xffffff9, 28}, {0xffffffa, 28}, {0xffffffb, 28},
	{0x14, 6}, {0x3f8, 10}, {0x3f9, 10}, {0xffa, 12}, {0x1ff9, 13}, {0x15, 6}, {0xf8, 8}, {0x7fa, 11},
	{0x3fa, 10}, {0x3fb, 10}, {0xf9, 8}, {0x7fb, 11}, {0xfa, 8}, {0x16, 6}, {0x17, 6}, {0x18, 6},
	{0x0, 5}, {0x1, 5}, {0x2, 5}, {0x19, 6}, {0x1a, 6}, {0x1b, 6}, {0x1c, 6}, {0x1d, 6},
	{0x1e, 6}, {0x1f, 6}, {0x5c, 7}, {0xfb, 8}, {0x7ffc, 15}, {0x20, 6}, {0xffb, 12}, {0x3fc, 10},
	{0x1ffa, 13}, {0x21, 6}, {0x5d, 7}, {0x5e, 7}, {0x5f, 7}, {0x60, 7}, {0x61, 7}, {0x62, 7},
	{0x63, 7}, {0x64, 7}, {0x65, 7}, {0x66, 7}, {0x67, 7}, {0x68, 7}, {0x69, 7}, {0x6a, 7},
	{0x6b, 7}, {0x6c, 7}, {0x6d, 7}, {0x6e, 7}, {0x6f, 7}, {0x70, 7}, {0x71, 7}, {0x72, 7},
	{0xfc, 8}, {0x73, 7}, {0xfd, 8}, {0x1ffb, 13}, {0x7fff0, 19}, {0x1ffc, 13}, {0x3ffc, 14}, {0x22, 6},
	{0x7ffd, 15}, {0x3, 5}, {0x23, 6}, {0x4, 5}, {0x24, 6}, {0x5, 5}, {0x25, 6}, {0x26, 6},
	{0x27, 6}, {0x6, 5}, {0x74, 7}, {0x75, 7}, {0x28, 6}, {0x29, 6}, {0x2a, 6}, {0x7, 5},
	{0x2b, 6}, {0x76, 7}, {0x2c, 6}, {0x8, 5}, {0x9, 5}, {0x2d, 6}, {0x77, 7}, {0x78, 7},
	{0x79, 7}, {0x7a, 7}, {0x7b, 7}, {0x7ffe, 15}, {0x7fc, 11}, {0x3ffd, 14}, {0x1ffd, 13}, {0xffffffc, 28},
	{0xfffe6, 20}, {0x3fffd2, 22}, {0xfffe7, 20}, {0xfffe8, 20}, {0x3fffd3, 22}, {0x3fffd4, 22}, {0x3fffd5, 22}, {0x7fffd9, 23},
	{0x3fffd6, 22}, {0x7fffda, 23}, {0x7fffdb, 23}, {0x7fffdc, 23}, {0x7fffdd, 23}, {0x7fffde, 23}, {0xffffeb, 24}, {0x7fffdf, 23},
	{0xffffec, 24}, {0xffffed, 24}, {0x3fffd7, 22}, {0x7fffe0, 23}, {0xffffee, 24}, {0x7fffe1, 23}, {0x7fffe2, 23}, {0x7fffe3, 23},
	{0x7fffe4, 23}, {0x1fffdc, 21}, {0x3fffd8, 22}, {0x7fffe5, 23}, {0x3fffd9, 22}, {0x7fffe6, 23}, {0x7fffe7, 23}, {0xffffef, 24},
	{0x3fffda, 22}, {0x1fffdd, 21}, {0xfffe9, 20}, {0x3fffdb, 22}, {0x3fffdc, 22}, {0x7fffe8, 23}, {0x7fffe9, 23}, {0x1fffde, 21},
	{0x7fffea, 23}, {0x3fffdd, 22}, {0x3fffde, 22}, {0xfffff0, 24}, {0x1fffdf, 21}, {0x3fffdf, 22}, {0x7fffeb, 23}, {0x7fffec, 23},
	{0x1fffe0, 21}, {0x1fffe1, 21}, {0x3fffe0, 22}, {0x1fffe2, 21}, {0x7fffed, 23}, {0x3fffe1, 22}, {0x7fffee, 23}, {0x7fffef, 23},
	{0xfffea, 20}, {0x3fffe2, 22}, {0x3fffe3, 22}, {0x3fffe4, 22}, {0x7ffff0, 23}, {0x3fffe5, 22}, {0x3fffe6, 22}, {0x7ffff1, 23},
	{0x3ffffe0, 26}, {0x3ffffe1, 26}, {0xfffeb, 20}, {0x7fff1, 19}, {0x3fffe7, 22}, {0x7ffff2, 23}, {0x3fffe8, 22}, {0x1ffffec, 25},
	{0x3ffffe2, 26}, {0x3ffffe3, 26}, {0x3ffffe4, 26}, {0x7ffffde, 27}, {0x7ffffdf, 27}, {0x3ffffe5, 26}, {0xfffff1, 24}, {0x1ffffed, 25},
	{0x7fff2, 19}, {0x1fffe3, 21}, {0x3ffffe6, 26}, {0x7ffffe0, 27}, {0x7ffffe1, 27}, {0x3ffffe7, 26}, {0x7ffffe2, 27}, {0xfffff2, 24},
	{0x1fffe4, 21}, {0x1fffe5, 21}, {0x3ffffe8, 26}, {0x3ffffe9, 26}, {0xffffffd, 28}, {0x7ffffe3, 27}, {0x7ffffe4, 27}, {0x7ffffe5, 27},
	{0xfffec, 20}, {0xfffff3, 24}, {0xfffed, 20}, {0x1fffe6, 21}, {0x3fffe9, 22}, {0x1fffe7, 21}, {0x1fffe8, 21}, {0x7ffff3, 23},
	{0x3fffea, 22}, {0x3fffeb, 22}, {0x1ffffee, 25}, {0x1ffffef, 25}, {0xfffff4, 24}, {0xfffff5, 24}, {0x3ffffea, 26}, {0x7ffff4, 23},
	{0x3ffffeb, 26}, {0x7ffffe6, 27}, {0x3ffffec, 26}, {0x3ffffed, 26}, {0x7ffffe7, 27}, {0x7ffffe8, 27}, {0x7ffffe9, 27}, {0x7ffffea, 27},
	{0x7ffffeb, 27}, {0xffffffe, 28}, {0x7ffffec, 27}, {0x7ffffed, 27}, {0x7ffffee, 27}, {0x7ffffef, 27}, {0x7fffff0, 27}, {0x3ffffee, 26},
}

func initHuffmanTrie() {
	root := &huffNode{}
	for sym, entry := range rfc7541HuffmanTable {
		cur := root
		for bitPos := int(entry.bits) - 1; bitPos >= 0; bitPos-- {
			b := (entry.code >> uint(bitPos)) & 1
			if cur.children[b] == nil {
				cur.children[b] = &huffNode{}
			}
			cur = cur.children[b]
		}
		cur.sym = byte(sym)
		cur.isLeaf = true
	}
	huffRoot = root
}

func huffmanDecode(src []byte) (string, error) {
	huffOnce.Do(initHuffmanTrie)
	out := make([]byte, 0, len(src)*2)
	cur := huffRoot
	var padBits int
	var allOnes = true

	for _, b := range src {
		for shift := 7; shift >= 0; shift-- {
			bit := (b >> uint(shift)) & 1
			cur = cur.children[bit]
			if cur == nil {
				return "", errors.New("invalid huffman sequence")
			}
			if bit == 0 {
				allOnes = false
			}
			padBits++
			if cur.isLeaf {
				out = append(out, cur.sym)
				cur = huffRoot
				padBits = 0
				allOnes = true
			}
		}
	}
	if padBits > 7 || !allOnes {
		return "", errors.New("invalid huffman padding")
	}
	return string(out), nil
}
