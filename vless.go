package main

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
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
	// 兼容 passwords 列表形式作为 UUID
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

func (h *vlessHandler) handle(ctx context.Context, c net.Conn) {
	ip := addrOf(c)
	_ = c.SetDeadline(time.Now().Add(h.lim.HandshakeTimeout.Duration))
	br := acquireReader(c)
	defer releaseReader(br)

	// 0. 协议嗅探与单端口智能复用（443 端口同时支持 VLESS-TLS、VLESS-WSS 与伪装站回落）
	if peek1, err := br.Peek(1); err == nil && peek1[0] != 0x00 {
		// 检查是否为 HTTP / WebSocket 升级请求 (例如 "GET /...")
		if peek4, err := br.Peek(4); err == nil && string(peek4) == "GET " {
			if peekHdr, _ := br.Peek(br.Buffered()); len(peekHdr) > 0 {
				hdrStr := string(peekHdr)
				if containsFold(hdrStr, "upgrade: websocket") {
					wsConn, err := UpgradeWebSocket(c, br, &WSConfig{})
					if err != nil {
						h.guard.Fail(ip)
						return
					}
					h.handle(ctx, wsConn)
					return
				}
			}
		}
		// 非 VLESS 且非 WebSocket（例如普通浏览器直接访问 https://aws.mzstd.xyz），零篡改透明回落到伪装站
		if h.fallback != "" {
			d := net.Dialer{Timeout: 3 * time.Second}
			if fb, err := d.DialContext(ctx, "tcp", h.fallback); err == nil {
				_ = c.SetDeadline(time.Time{})
				relay(&bufConn{Conn: c, r: br}, fb, h.lim.IdleTimeout.Duration)
				return
			}
		}
		h.guard.Fail(ip)
		return
	}

	// 1. 读取 VLESS 版本 (1B)
	ver, err := br.ReadByte()
	if err != nil || ver != 0 {
		h.guard.Fail(ip)
		return
	}

	// 2. 校验 UUID (16B)
	var reqUUID [16]byte
	if _, err := io.ReadFull(br, reqUUID[:]); err != nil {
		h.guard.Fail(ip)
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
		h.guard.Fail(ip)
		// 如果配置了回落，将探测流量交由 fallback
		if h.fallback != "" {
			d := net.Dialer{Timeout: 3 * time.Second}
			fb, err := d.DialContext(ctx, "tcp", h.fallback)
			if err == nil {
				// 将已读出的 version + uuid 写回 fallback
				_, _ = fb.Write([]byte{ver})
				_, _ = fb.Write(reqUUID[:])
				relay(&bufConn{Conn: c, r: br}, fb, h.lim.IdleTimeout.Duration)
			}
		}
		return
	}

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

	// 4. 读取指令 (0x01: TCP, 0x02: UDP)
	cmd, err := br.ReadByte()
	if err != nil {
		return
	}

	// 5. 读取端口与目标地址
	var portBytes [2]byte
	if _, err := io.ReadFull(br, portBytes[:]); err != nil {
		return
	}
	dstPort := int(binary.BigEndian.Uint16(portBytes[:]))

	atyp, err := br.ReadByte()
	if err != nil {
		return
	}

	var dstHost string
	switch atyp {
	case 1: // IPv4
		var ipBytes [4]byte
		if _, err := io.ReadFull(br, ipBytes[:]); err != nil {
			return
		}
		dstHost = net.IP(ipBytes[:]).String()
	case 2: // Domain
		dlen, err := br.ReadByte()
		if err != nil || dlen == 0 {
			return
		}
		name := make([]byte, dlen)
		if _, err := io.ReadFull(br, name); err != nil {
			return
		}
		dstHost = string(name)
	case 3: // IPv6
		var ipBytes [16]byte
		if _, err := io.ReadFull(br, ipBytes[:]); err != nil {
			return
		}
		dstHost = net.IP(ipBytes[:]).String()
	default:
		h.guard.Fail(ip)
		return
	}

	// 6. 服务端发送 VLESS 响应头: [Version 0x00] [Addons Len 0x00]
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
		h.handleVLESSUDP(ctx, c, br, dstHost, dstPort)

	default:
		h.guard.Fail(ip)
	}
}

// handleVLESSUDP 在 VLESS 连接上中继 UDP 数据流（每帧格式: [Len 2B] [Payload]）
func (h *vlessHandler) handleVLESSUDP(ctx context.Context, c net.Conn, br *bufio.Reader, initHost string, initPort int) {
	clientKey := fmt.Sprintf("vless:%s", c.RemoteAddr().String())
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
			writeMu.Lock()
			defer writeMu.Unlock()

			var l [2]byte
			binary.BigEndian.PutUint16(l[:], uint16(len(respPayload)))

			_ = c.SetWriteDeadline(time.Now().Add(h.lim.IdleTimeout.Duration))
			if _, err := c.Write(l[:]); err != nil {
				return err
			}
			_, err := c.Write(respPayload)
			return err
		})
	}
}
