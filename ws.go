package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
)

var (
	wsGUID          = []byte("258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
	errInvalidWS    = errors.New("invalid websocket upgrade request")
	errClosedWS     = errors.New("websocket connection closed")
	errWSFrameLarge = errors.New("websocket frame exceeds max size")
)

// WSConfig WebSocket 传输层配置（专用于 Cloudflare 等 CDN 反向代理中转）
type WSConfig struct {
	Path        string            `json:"path"`         // 匹配的 HTTP 路径，例如 "/vless-ws"
	Host        string            `json:"host"`         // 校验的 Host 头（可选）
	Headers     map[string]string `json:"headers"`      // 校验的自定义 HTTP 头（可选）
	MaxFrameLen int               `json:"max_frame_len"`// 最大单帧长度（默认 65535）
}

// wsConn 将底层 TCP/TLS 流包装为全双工 WebSocket 二进制帧流，实现 net.Conn 接口
type wsConn struct {
	net.Conn
	r          *bufio.Reader
	remoteAddr net.Addr
	readLeft   []byte
	wmu        sync.Mutex
	maxLen     int
}

func (c *wsConn) RemoteAddr() net.Addr {
	if c.remoteAddr != nil {
		return c.remoteAddr
	}
	return c.Conn.RemoteAddr()
}

func (c *wsConn) Read(p []byte) (int, error) {
	if len(c.readLeft) > 0 {
		n := copy(p, c.readLeft)
		c.readLeft = c.readLeft[n:]
		return n, nil
	}

	for {
		// 读取 RFC 6455 帧头（最少 2 字节）
		var b [2]byte
		if _, err := io.ReadFull(c.r, b[:]); err != nil {
			return 0, err
		}

		fin := (b[0] & 0x80) != 0
		opcode := b[0] & 0x0F
		masked := (b[1] & 0x80) != 0
		lenCode := int(b[1] & 0x7F)

		var payloadLen int
		switch lenCode {
		case 126:
			var s [2]byte
			if _, err := io.ReadFull(c.r, s[:]); err != nil {
				return 0, err
			}
			payloadLen = int(binary.BigEndian.Uint16(s[:]))
		case 127:
			var l [8]byte
			if _, err := io.ReadFull(c.r, l[:]); err != nil {
				return 0, err
			}
			payloadLen = int(binary.BigEndian.Uint64(l[:]))
		default:
			payloadLen = lenCode
		}

		if payloadLen > c.maxLen {
			return 0, errWSFrameLarge
		}

		var maskKey [4]byte
		if masked {
			if _, err := io.ReadFull(c.r, maskKey[:]); err != nil {
				return 0, err
			}
		}

		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(c.r, payload); err != nil {
			return 0, err
		}

		if masked {
			for i := 0; i < payloadLen; i++ {
				payload[i] ^= maskKey[i%4]
			}
		}

		switch opcode {
		case 0x00, 0x01, 0x02: // 分片延续帧 / 文本帧 / 二进制帧
			n := copy(p, payload)
			c.readLeft = payload[n:]
			return n, nil

		case 0x08: // 关闭帧 (Close)
			return 0, io.EOF

		case 0x09: // 心跳 Ping -> 响应 Pong (0x0A)
			if len(payload) > 125 {
				return 0, errors.New("ping payload exceeds 125 bytes")
			}
			c.wmu.Lock()
			_ = c.writeControlFrame(0x0A, payload)
			c.wmu.Unlock()

		case 0x0A: // 心跳 Pong -> 忽略
			continue

		default:
			continue
		}
	}
}

func (c *wsConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()

	total := len(p)
	for len(p) > 0 {
		chunk := p
		if len(chunk) > c.maxLen {
			chunk = p[:c.maxLen]
		}
		p = p[len(chunk):]

		// 服务端回传 WebSocket 帧默认不掩码 (Unmasked)
		var hdr [10]byte
		hdr[0] = 0x82 // FIN + Binary Frame (0x02)
		var hlen int

		n := len(chunk)
		if n < 126 {
			hdr[1] = byte(n)
			hlen = 2
		} else if n <= 65535 {
			hdr[1] = 126
			binary.BigEndian.PutUint16(hdr[2:4], uint16(n))
			hlen = 4
		} else {
			hdr[1] = 127
			binary.BigEndian.PutUint64(hdr[2:10], uint64(n))
			hlen = 10
		}

		if _, err := c.Conn.Write(hdr[:hlen]); err != nil {
			return 0, err
		}
		if _, err := c.Conn.Write(chunk); err != nil {
			return 0, err
		}
	}
	return total, nil
}

func (c *wsConn) writeControlFrame(opcode byte, data []byte) error {
	var hdr [2]byte
	hdr[0] = 0x80 | (opcode & 0x0F)
	hdr[1] = byte(len(data) & 0x7F)
	if _, err := c.Conn.Write(hdr[:]); err != nil {
		return err
	}
	if len(data) > 0 {
		_, err := c.Conn.Write(data)
		return err
	}
	return nil
}

// UpgradeWebSocket 完成 HTTP Upgrade 握手，提取真实客户端 IP，并返回包装后的 net.Conn
func UpgradeWebSocket(raw net.Conn, br *bufio.Reader, cfg *WSConfig) (net.Conn, error) {
	req, err := http.ReadRequest(br)
	if err != nil {
		return nil, fmt.Errorf("read upgrade request: %w", err)
	}

	// 1. 路径校验
	if cfg != nil && cfg.Path != "" {
		reqPath := req.URL.Path
		if !strings.HasPrefix(reqPath, cfg.Path) {
			_, _ = raw.Write([]byte("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
			return nil, fmt.Errorf("ws path mismatch: got %q, want prefix %q", reqPath, cfg.Path)
		}
	}

	// 1.1 Host 校验（若配置）
	if cfg != nil && cfg.Host != "" {
		reqHost := req.Host
		if h, _, err := net.SplitHostPort(reqHost); err == nil {
			reqHost = h
		}
		if !strings.EqualFold(reqHost, cfg.Host) {
			_, _ = raw.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
			return nil, fmt.Errorf("ws host mismatch: got %q, want %q", req.Host, cfg.Host)
		}
	}

	// 1.2 自定义 Headers 校验（若配置）
	if cfg != nil && len(cfg.Headers) > 0 {
		for k, v := range cfg.Headers {
			if req.Header.Get(k) != v {
				_, _ = raw.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
				return nil, fmt.Errorf("ws header mismatch for %q", k)
			}
		}
	}

	// 2. 协议头升级校验
	if !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		_, _ = raw.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		return nil, errInvalidWS
	}

	key := req.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		_, _ = raw.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		return nil, errors.New("missing Sec-WebSocket-Key")
	}

	// 3. 计算 Sec-WebSocket-Accept = Base64(SHA1(Key + GUID))
	h := sha1.New()
	h.Write([]byte(key))
	h.Write(wsGUID)
	accept := base64.StdEncoding.EncodeToString(h.Sum(nil))

	// 4. 解析真实客户端 IP（关键：支持 Cloudflare CF-Connecting-IP 与 X-Forwarded-For）
	realIP := extractRealClientIP(req)
	var resolvedRemote net.Addr = raw.RemoteAddr()
	if realIP != nil {
		if ta, ok := raw.RemoteAddr().(*net.TCPAddr); ok {
			resolvedRemote = &net.TCPAddr{IP: realIP, Port: ta.Port}
		}
	}

	// 5. 响应 101 Switching Protocols
	resp := fmt.Sprintf("HTTP/1.1 101 Switching Protocols\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Accept: %s\r\n\r\n", accept)

	if _, err := raw.Write([]byte(resp)); err != nil {
		return nil, err
	}

	maxLen := 65535
	if cfg != nil && cfg.MaxFrameLen > 0 {
		maxLen = cfg.MaxFrameLen
	}

	return &wsConn{
		Conn:       raw,
		r:          br,
		remoteAddr: resolvedRemote,
		maxLen:     maxLen,
	}, nil
}

// extractRealClientIP 提取 CDN 回源头中的真实访客 IP，杜绝 Cloudflare CDN 节点 IP 触发误封
func extractRealClientIP(req *http.Request) net.IP {
	// 优先读取 Cloudflare 特有标头
	if cfIP := req.Header.Get("CF-Connecting-IP"); cfIP != "" {
		if ip := net.ParseIP(strings.TrimSpace(cfIP)); ip != nil {
			return ip
		}
	}
	// 备选读取 X-Real-IP
	if xri := req.Header.Get("X-Real-IP"); xri != "" {
		if ip := net.ParseIP(strings.TrimSpace(xri)); ip != nil {
			return ip
		}
	}
	// 备选读取 X-Forwarded-For（取首个非内网 IP）
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		for _, part := range parts {
			clean := strings.TrimSpace(part)
			if ip := net.ParseIP(clean); ip != nil {
				if nip, err := netip.ParseAddr(ip.String()); err == nil && !nip.IsPrivate() && !nip.IsLoopback() {
					return ip
				}
			}
		}
	}
	return nil
}
