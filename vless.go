package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

var (
	errVlessAuth    = errors.New("vless: authentication failed")
	errVlessVersion = errors.New("vless: unsupported version")
)

type vlessHandler struct {
	uuids    map[[16]byte]string // UUID -> Username
	out      *Outbound
	guard    *Guard
	lim      Limits
	udpMgr   *UDPManager
	fallback string
}

func parseUUID(s string) ([16]byte, error) {
	var u [16]byte
	clean := make([]byte, 0, 32)
	for i := 0; i < len(s); i++ {
		if s[i] != '-' {
			clean = append(clean, s[i])
		}
	}
	if len(clean) != 32 {
		return u, errors.New("invalid uuid length")
	}
	for i := 0; i < 16; i++ {
		var b byte
		for j := 0; j < 2; j++ {
			c := clean[i*2+j]
			var val byte
			switch {
			case c >= '0' && c <= '9':
				val = c - '0'
			case c >= 'a' && c <= 'f':
				val = c - 'a' + 10
			case c >= 'A' && c <= 'F':
				val = c - 'A' + 10
			default:
				return u, errors.New("invalid uuid character")
			}
			b = (b << 4) | val
		}
		u[i] = b
	}
	return u, nil
}

func newVLESSHandler(lc ListenerConfig, out *Outbound, g *Guard, lim Limits, udpMgr *UDPManager) (*vlessHandler, error) {
	h := &vlessHandler{
		uuids:    make(map[[16]byte]string),
		out:      out,
		guard:    g,
		lim:      lim,
		udpMgr:   udpMgr,
		fallback: lc.Fallback,
	}
	for user, idStr := range lc.Users {
		u, err := parseUUID(idStr)
		if err != nil {
			return nil, fmt.Errorf("user %s invalid uuid: %w", user, err)
		}
		h.uuids[u] = user
	}
	for _, idStr := range lc.Passwords {
		u, err := parseUUID(idStr)
		if err != nil {
			return nil, fmt.Errorf("password %q is not a valid uuid: %w", idStr, err)
		}
		h.uuids[u] = idStr
	}
	if len(h.uuids) == 0 {
		return nil, errors.New("vless requires at least one valid uuid")
	}
	return h, nil
}

func isHTTPMethodPrefix(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	switch string(b[:4]) {
	case "GET ", "POST", "HEAD", "PUT ", "OPTI", "DELE", "PATC":
		return true
	default:
		return false
	}
}

func (h *vlessHandler) handle(ctx context.Context, c net.Conn) {
	ip := addrOf(c)
	_ = c.SetDeadline(time.Now().Add(h.lim.HandshakeTimeout.Duration))
	br := acquireReader(c)
	defer releaseReader(br)

	// 0. 协议嗅探与单端口智能复用（443 端口同时支持 VLESS-TLS、跨 Record 大包 VLESS-WSS 与伪装站回落）
	peek1, err := br.Peek(1)
	if err != nil {
		// 客户端空闲预连接关闭 (io.EOF) 或正常超时不计入攻击封禁
		return
	}
	if peek1[0] != 0x00 {
		if peek4, pErr := br.Peek(4); pErr == nil && isHTTPMethodPrefix(peek4) {
			// 完整读取跨越多个 TLS Record 的 HTTP 头部（根治 ?ed=2048 携带大 ClientHello 时的 200 OK 误回落）
			req, rErr := http.ReadRequest(br)
			if rErr != nil {
				return
			}
			if containsFold(req.Header.Get("Upgrade"), "websocket") {
				wsC, uErr := UpgradeWebSocketWithRequest(c, br, req, &WSConfig{})
				if uErr != nil {
					return
				}
				h.handle(ctx, wsC)
				return
			}
			// 普通浏览器访问 HTTPS 伪装站，透明转发已解析请求，不触发封禁
			if h.fallback != "" {
				d := net.Dialer{Timeout: 3 * time.Second}
				if fb, dErr := d.DialContext(ctx, "tcp", h.fallback); dErr == nil {
					_ = c.SetDeadline(time.Time{})
					_ = req.Write(fb)
					relay(&bufConn{Conn: c, r: br}, fb, h.lim.IdleTimeout.Duration)
					return
				}
			}
			return
		}

		if h.fallback != "" {
			d := net.Dialer{Timeout: 3 * time.Second}
			if fb, dErr := d.DialContext(ctx, "tcp", h.fallback); dErr == nil {
				_ = c.SetDeadline(time.Time{})
				relay(&bufConn{Conn: c, r: br}, fb, h.lim.IdleTimeout.Duration)
				return
			}
		}
		return
	}

	// 1. 读取 VLESS 版本 (1B == 0x00)
	ver, err := br.ReadByte()
	if err != nil || ver != 0 {
		return
	}

	// 2. 校验 UUID (16B)
	var reqUUID [16]byte
	if _, err := io.ReadFull(br, reqUUID[:]); err != nil {
		return
	}

	userFound := false
	for u := range h.uuids {
		if subtle.ConstantTimeCompare(u[:], reqUUID[:]) == 1 {
			userFound = true
			break
		}
	}
	if !userFound {
		// 明确的非法 UUID 认证失败才记入 Guard
		h.guard.Fail(ip)
		if h.fallback != "" {
			d := net.Dialer{Timeout: 3 * time.Second}
			if fb, dErr := d.DialContext(ctx, "tcp", h.fallback); dErr == nil {
				_, _ = fb.Write([]byte{ver})
				_, _ = fb.Write(reqUUID[:])
				_ = c.SetDeadline(time.Time{})
				relay(&bufConn{Conn: c, r: br}, fb, h.lim.IdleTimeout.Duration)
			}
		}
		return
	}

	// 认证通过：将客户端 IP 加入动态信任白名单，免疫后续误封
	h.guard.AuthSuccess(ip)

	// 3. 读取附加数据流 (Addons)
	addonLen, err := br.ReadByte()
	if err != nil {
		return
	}
	if addonLen > 0 {
		addonBuf := make([]byte, addonLen)
		if _, err := io.ReadFull(br, addonBuf); err != nil {
			return
		}
	}

	// 4. 读取指令 (0x01: TCP, 0x02: UDP, 0x03: Mux/XUDP)
	cmd, err := br.ReadByte()
	if err != nil {
		return
	}

	if cmd == 0x03 {
		// Mux.Cool / XUDP 模式：请求头不含单目标地址，直接发送响应头后进入多路复用帧循环
		if _, err := c.Write([]byte{0x00, 0x00}); err != nil {
			return
		}
		_ = c.SetDeadline(time.Time{})
		h.handleVLESSXUDP(ctx, c, br)
		return
	}

	if cmd != 0x01 && cmd != 0x02 {
		return
	}

	// 5. 读取端口与目标地址 (Port 2B + VLESS ATYP + Addr)
	dstHost, dstPort, err := readVLESSAddr(br)
	if err != nil {
		return
	}

	// 6. 发送 VLESS 响应头: [Version 0x00] [Addons Len 0x00]
	if _, err := c.Write([]byte{0x00, 0x00}); err != nil {
		return
	}

	_ = c.SetDeadline(time.Time{})

	switch cmd {
	case 0x01: // TCP
		dctx, cancel := context.WithTimeout(ctx, h.lim.HandshakeTimeout.Duration)
		up, err := h.out.Dial(dctx, dstHost, dstPort)
		cancel()
		if err != nil {
			slog.Debug("vless tcp dial failed", "dst", hostPort(dstHost, dstPort), "err", err)
			return
		}
		relay(&bufConn{Conn: c, r: br}, up, h.lim.IdleTimeout.Duration)

	case 0x02: // UDP
		if h.udpMgr != nil {
			h.handleVLESSUDP(ctx, c, br, dstHost, dstPort)
		}
	}
}

func readVLESSAddr(r io.Reader) (host string, port int, err error) {
	var portBytes [2]byte
	if _, err = io.ReadFull(r, portBytes[:]); err != nil {
		return "", 0, err
	}
	port = int(binary.BigEndian.Uint16(portBytes[:]))

	var atyp [1]byte
	if _, err = io.ReadFull(r, atyp[:]); err != nil {
		return "", 0, err
	}
	switch atyp[0] {
	case 1: // IPv4
		var ipBytes [4]byte
		if _, err = io.ReadFull(r, ipBytes[:]); err != nil {
			return "", 0, err
		}
		host = netip.AddrFrom4(ipBytes).String()
	case 2: // Domain
		var dlen [1]byte
		if _, err = io.ReadFull(r, dlen[:]); err != nil || dlen[0] == 0 {
			return "", 0, errBadAddr
		}
		name := make([]byte, dlen[0])
		if _, err = io.ReadFull(r, name); err != nil {
			return "", 0, err
		}
		host = string(name)
	case 3: // IPv6
		var ipBytes [16]byte
		if _, err = io.ReadFull(r, ipBytes[:]); err != nil {
			return "", 0, err
		}
		host = netip.AddrFrom16(ipBytes).String()
	default:
		return "", 0, errBadAddr
	}
	return host, port, nil
}

func appendVLESSAddr(buf []byte, host string, port int) []byte {
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], uint16(port))
	buf = append(buf, p[:]...)
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			b := ip.As4()
			buf = append(buf, 0x01)
			buf = append(buf, b[:]...)
			return buf
		}
		b := ip.As16()
		buf = append(buf, 0x03)
		buf = append(buf, b[:]...)
		return buf
	}
	buf = append(buf, 0x02, byte(len(host)))
	buf = append(buf, host...)
	return buf
}

// handleVLESSUDP 在 VLESS 连接上中继标准 UDP 数据流（单次 Write 合并帧头与载荷，独立会话 ID 杜绝串流）
func (h *vlessHandler) handleVLESSUDP(ctx context.Context, c net.Conn, br *bufio.Reader, initHost string, initPort int) {
	clientKey := fmt.Sprintf("vless:%d", udpSeq.Add(1))
	defer h.udpMgr.RemoveSession(clientKey)
	var writeMu sync.Mutex

	for {
		_ = c.SetReadDeadline(time.Now().Add(h.lim.IdleTimeout.Duration))
		var lenBytes [2]byte
		if _, err := io.ReadFull(br, lenBytes[:]); err != nil {
			return
		}
		payloadLen := int(binary.BigEndian.Uint16(lenBytes[:]))
		if payloadLen == 0 || payloadLen > 65535 {
			return
		}

		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(br, payload); err != nil {
			return
		}

		_ = h.udpMgr.SendPacket(clientKey, initHost, initPort, payload, func(respHost string, respPort int, respPayload []byte) error {
			if len(respPayload) > 65535 {
				return nil
			}
			pkt := make([]byte, 2+len(respPayload))
			binary.BigEndian.PutUint16(pkt[0:2], uint16(len(respPayload)))
			copy(pkt[2:], respPayload)

			writeMu.Lock()
			defer writeMu.Unlock()
			_ = c.SetWriteDeadline(time.Now().Add(h.lim.IdleTimeout.Duration))
			_, err := c.Write(pkt)
			return err
		})
	}
}

// handleVLESSXUDP 支持 Xray / sing-box / Clash.Meta 的 XUDP (cmd=0x03) 多路复用 UDP 转发
func (h *vlessHandler) handleVLESSXUDP(ctx context.Context, c net.Conn, br *bufio.Reader) {
	if h.udpMgr == nil {
		return
	}
	connID := udpSeq.Add(1)
	var writeMu sync.Mutex

	type udpTarget struct {
		host string
		port int
	}
	targets := make(map[uint16]udpTarget)
	sessKeys := make(map[uint16]string)

	defer func() {
		for _, k := range sessKeys {
			h.udpMgr.RemoveSession(k)
		}
	}()

	for {
		_ = c.SetReadDeadline(time.Now().Add(h.lim.IdleTimeout.Duration))
		var metaLenBytes [2]byte
		if _, err := io.ReadFull(br, metaLenBytes[:]); err != nil {
			return
		}
		metaLen := int(binary.BigEndian.Uint16(metaLenBytes[:]))
		if metaLen < 4 || metaLen > 4096 {
			return
		}

		meta := make([]byte, metaLen)
		if _, err := io.ReadFull(br, meta); err != nil {
			return
		}

		sessID := binary.BigEndian.Uint16(meta[0:2])
		status := meta[2] // 0x01=New, 0x02=Keep, 0x03=End, 0x04=KeepAlive
		opt := meta[3]    // bit 0 (0x01) = OptionData

		if (status == 0x01 || status == 0x02) && len(meta) >= 8 {
			netType := meta[4]
			if netType == 0x02 { // UDP
				if tHost, tPort, err := readVLESSAddr(bytes.NewReader(meta[5:])); err == nil && tPort > 0 {
					targets[sessID] = udpTarget{host: tHost, port: tPort}
				}
			}
		}

		var payload []byte
		if opt&0x01 != 0 {
			var plenBytes [2]byte
			if _, err := io.ReadFull(br, plenBytes[:]); err != nil {
				return
			}
			plen := int(binary.BigEndian.Uint16(plenBytes[:]))
			if plen > 0 {
				payload = make([]byte, plen)
				if _, err := io.ReadFull(br, payload); err != nil {
					return
				}
			}
		}

		if status == 0x03 { // SessionEnd
			if k, exists := sessKeys[sessID]; exists {
				h.udpMgr.RemoveSession(k)
				delete(sessKeys, sessID)
			}
			delete(targets, sessID)
			continue
		}

		if len(payload) == 0 {
			continue
		}
		dst, ok := targets[sessID]
		if !ok {
			continue
		}

		key, exists := sessKeys[sessID]
		if !exists {
			key = fmt.Sprintf("xudp:%d:%d", connID, sessID)
			sessKeys[sessID] = key
		}

		sID := sessID
		_ = h.udpMgr.SendPacket(key, dst.host, dst.port, payload, func(respHost string, respPort int, respPayload []byte) error {
			if len(respPayload) > 65535 {
				return nil
			}
			respMeta := make([]byte, 5, 32)
			binary.BigEndian.PutUint16(respMeta[0:2], sID)
			respMeta[2] = 0x02 // SessionStatusKeep
			respMeta[3] = 0x01 // OptionData
			respMeta[4] = 0x02 // Network: UDP
			respMeta = appendVLESSAddr(respMeta, respHost, respPort)

			frame := make([]byte, 2+len(respMeta)+2+len(respPayload))
			binary.BigEndian.PutUint16(frame[0:2], uint16(len(respMeta)))
			copy(frame[2:2+len(respMeta)], respMeta)
			off := 2 + len(respMeta)
			binary.BigEndian.PutUint16(frame[off:off+2], uint16(len(respPayload)))
			copy(frame[off+2:], respPayload)

			writeMu.Lock()
			defer writeMu.Unlock()
			_ = c.SetWriteDeadline(time.Now().Add(h.lim.IdleTimeout.Duration))
			_, err := c.Write(frame)
			return err
		})
	}
}
