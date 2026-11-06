package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"
)

// RealityConfig Reality 伪装配置：借用真实海外大站证书，消除服务端 TLS 特征并反弹主动探测
type RealityConfig struct {
	Dest        string   `json:"dest"`         // 真实伪装目标地址，例如 "www.microsoft.com:443" 或 "gateway.icloud.com:443"
	ServerNames []string `json:"server_names"` // 允许的 SNI 列表
	ShortIDs    []string `json:"short_ids"`    // 客户端鉴权短 ID 列表（十六进制）
}

type realityHandler struct {
	dest        string
	serverNames map[string]struct{}
	shortIDs    map[string]struct{}
	inner       Handler
	guard       *Guard
	lim         Limits
}

func newRealityHandler(cfg *RealityConfig, inner Handler, g *Guard, lim Limits) (*realityHandler, error) {
	if cfg == nil || cfg.Dest == "" {
		return nil, errors.New("reality requires dest (e.g. www.microsoft.com:443)")
	}
	h := &realityHandler{
		dest:        cfg.Dest,
		serverNames: make(map[string]struct{}),
		shortIDs:    make(map[string]struct{}),
		inner:       inner,
		guard:       g,
		lim:         lim,
	}
	for _, sn := range cfg.ServerNames {
		h.serverNames[strings.ToLower(sn)] = struct{}{}
	}
	for _, sid := range cfg.ShortIDs {
		h.shortIDs[strings.ToLower(sid)] = struct{}{}
	}
	return h, nil
}

// sniffClientHello 嗅探并解析 TLS ClientHello，提取 SNI 与 SessionID，同时保留已读字节
func sniffClientHello(r *bufio.Reader) (sni string, sessionID []byte, rawHello []byte, err error) {
	// TLS Record Header: 5 字节 [0x16, 0x03, 0x01/0x03, Length 2B]
	header, err := r.Peek(5)
	if err != nil {
		return "", nil, nil, err
	}
	if header[0] != 0x16 { // 不是 TLS Handshake
		return "", nil, nil, errors.New("not a tls handshake")
	}
	recordLen := int(header[3])<<8 | int(header[4])
	if recordLen < 4 || recordLen > 16384 {
		return "", nil, nil, errors.New("invalid tls record length")
	}

	totalLen := 5 + recordLen
	rawHello, err = r.Peek(totalLen)
	if err != nil {
		return "", nil, nil, err
	}

	// Handshake Type: 1 字节 (0x01 为 ClientHello)
	if rawHello[5] != 0x01 {
		return "", nil, nil, errors.New("not a client hello")
	}

	// ClientHello 内部结构解析
	idx := 5 + 4 // 跳过 Handshake Header (Type 1B + Length 3B)
	if idx+34 > len(rawHello) {
		return "", nil, nil, errors.New("truncated client hello")
	}
	idx += 34 // 跳过 Version(2B) + Random(32B)

	// Session ID
	if idx+1 > len(rawHello) {
		return "", nil, nil, errors.New("truncated session id len")
	}
	sessIDLen := int(rawHello[idx])
	idx++
	if idx+sessIDLen > len(rawHello) {
		return "", nil, nil, errors.New("truncated session id")
	}
	if sessIDLen > 0 {
		sessionID = make([]byte, sessIDLen)
		copy(sessionID, rawHello[idx:idx+sessIDLen])
	}
	idx += sessIDLen

	// Cipher Suites
	if idx+2 > len(rawHello) {
		return "", nil, nil, errors.New("truncated cipher suites")
	}
	csLen := int(rawHello[idx])<<8 | int(rawHello[idx+1])
	idx += 2 + csLen

	// Compression Methods
	if idx+1 > len(rawHello) {
		return "", nil, nil, errors.New("truncated compression")
	}
	compLen := int(rawHello[idx])
	idx += 1 + compLen

	// Extensions
	if idx+2 > len(rawHello) {
		return "", sessionID, rawHello, nil // 无扩展
	}
	extTotalLen := int(rawHello[idx])<<8 | int(rawHello[idx+1])
	idx += 2
	end := idx + extTotalLen
	if end > len(rawHello) {
		end = len(rawHello)
	}

	for idx+4 <= end {
		extType := int(rawHello[idx])<<8 | int(rawHello[idx+1])
		extLen := int(rawHello[idx+2])<<8 | int(rawHello[idx+3])
		idx += 4
		if idx+extLen > end {
			break
		}
		if extType == 0x0000 { // Server Name Indication (SNI)
			sniData := rawHello[idx : idx+extLen]
			if len(sniData) > 5 {
				nameLen := int(sniData[3])<<8 | int(sniData[4])
				if 5+nameLen <= len(sniData) {
					sni = strings.ToLower(string(sniData[5 : 5+nameLen]))
				}
			}
		}
		idx += extLen
	}

	return sni, sessionID, rawHello, nil
}

func (h *realityHandler) handle(ctx context.Context, c net.Conn) {
	ip := addrOf(c)
	_ = c.SetDeadline(time.Now().Add(h.lim.HandshakeTimeout.Duration))
	br := bufio.NewReaderSize(c, 8192)

	sni, sessID, _, err := sniffClientHello(br)
	if err != nil {
		// 非 TLS 请求，直接回落透传到真实目标站
		h.fallbackToDest(ctx, c, br)
		return
	}

	// 校验 SNI 是否在允许列表（如果配置了 server_names）
	if len(h.serverNames) > 0 {
		if _, ok := h.serverNames[sni]; !ok {
			h.guard.Fail(ip)
			h.fallbackToDest(ctx, c, br)
			return
		}
	}

	// 校验 Reality 鉴权密钥（ShortID）：
	// 客户端在 TLS ClientHello 的 SessionID 前缀中嵌入 ShortID
	authOK := false
	if len(h.shortIDs) == 0 {
		// 未限制 short_id 时直接放行至内层协议
		authOK = true
	} else if len(sessID) >= 8 {
		sessHex := fmt.Sprintf("%x", sessID)
		for sid := range h.shortIDs {
			if strings.HasPrefix(sessHex, sid) {
				authOK = true
				break
			}
		}
	}

	if !authOK {
		// 主动探测器 / 未授权扫描 / 普通浏览器访问：
		// 透明直连真实海外目标站（如 www.microsoft.com:443）！
		// 探测器将完成真实的微软 TLS 握手，获得微软真实证书，完全无法识别本代理！
		h.guard.Fail(ip)
		h.fallbackToDest(ctx, c, br)
		return
	}

	// 鉴权通过：进入内层代理协议（VLESS / Trojan）
	_ = c.SetDeadline(time.Time{})
	client := &bufConn{Conn: c, r: br}
	h.inner(ctx, client)
}

// fallbackToDest 将探测流量零篡改重定向给真实海外大站，完全伪装目标站行为
func (h *realityHandler) fallbackToDest(ctx context.Context, c net.Conn, br *bufio.Reader) {
	d := net.Dialer{Timeout: 5 * time.Second}
	target, err := d.DialContext(ctx, "tcp", h.dest)
	if err != nil {
		slog.Debug("reality fallback connect failed", "dest", h.dest, "err", err)
		return
	}
	_ = c.SetDeadline(time.Time{})
	relay(&bufConn{Conn: c, r: br}, target, h.lim.IdleTimeout.Duration)
}
