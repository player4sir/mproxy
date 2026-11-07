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

	wsWritePool = sync.Pool{
		New: func() any {
			b := make([]byte, 65535+16)
			return &b
		},
	}
)

// WSConfig WebSocket 传输层配置（专用于 Cloudflare 等 CDN 反向代理中转及直连 WSS）
type WSConfig struct {
	Path        string            `json:"path"`          // 匹配的 HTTP 路径，例如 "/vless-ws"
	Host        string            `json:"host"`          // 校验的 Host 头（可选）
	Headers     map[string]string `json:"headers"`       // 校验的自定义 HTTP 头（可选）
	MaxFrameLen int               `json:"max_frame_len"` // 最大单帧长度（默认 65535）
}

// wsConn 将底层 TCP/TLS 流包装为全双工 WebSocket 二进制帧流，实现完整 net.Conn + closeWriter 接口
type wsConn struct {
	net.Conn
	r           *bufio.Reader
	remoteAddr  net.Addr
	readLeft    []byte
	wmu         sync.Mutex
	closedWrite bool
	maxLen      int
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
		var b [2]byte
		if _, err := io.ReadFull(c.r, b[:]); err != nil {
			return 0, err
		}

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

// Write 将帧头与负载拼合后执行单次底层 Write，减少 50% 系统调用与外层 TLS Record 切片开销
func (c *wsConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()

	total := len(p)
	bp := wsWritePool.Get().(*[]byte)
	defer wsWritePool.Put(bp)
	frameBuf := *bp

	for len(p) > 0 {
		maxChunk := c.maxLen
		if maxChunk > 65535 {
			maxChunk = 65535
		}
		chunk := p
		if len(chunk) > maxChunk {
			chunk = p[:maxChunk]
		}
		p = p[len(chunk):]

		n := len(chunk)
		var hlen int
		frameBuf[0] = 0x82 // FIN + Binary Frame (0x02)
		if n < 126 {
			frameBuf[1] = byte(n)
			hlen = 2
		} else {
			frameBuf[1] = 126
			binary.BigEndian.PutUint16(frameBuf[2:4], uint16(n))
			hlen = 4
		}

		copy(frameBuf[hlen:], chunk)
		if _, err := c.Conn.Write(frameBuf[:hlen+n]); err != nil {
			return 0, err
		}
	}
	return total, nil
}

// CloseWrite 发送标准 RFC 6455 Close 帧并半关闭写端，避免客户端报 close 1006 unexpected EOF
func (c *wsConn) CloseWrite() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closedWrite {
		return nil
	}
	c.closedWrite = true
	_ = c.writeControlFrame(0x08, nil)
	closeWrite(c.Conn)
	return nil
}

func (c *wsConn) writeControlFrame(opcode byte, data []byte) error {
	var frame [130]byte
	frame[0] = 0x80 | (opcode & 0x0F)
	frame[1] = byte(len(data) & 0x7F)
	n := copy(frame[2:], data)
	_, err := c.Conn.Write(frame[:2+n])
	return err
}

// UpgradeWebSocket 读取 HTTP 请求并执行 WebSocket 协议升级
func UpgradeWebSocket(raw net.Conn, br *bufio.Reader, cfg *WSConfig) (net.Conn, error) {
	req, err := http.ReadRequest(br)
	if err != nil {
		return nil, fmt.Errorf("read upgrade request: %w", err)
	}
	return UpgradeWebSocketWithRequest(raw, br, req, cfg)
}

// UpgradeWebSocketWithRequest 复用已解析的 *http.Request 完成握手及 ?ed=2048 0-RTT 首包提取
func UpgradeWebSocketWithRequest(raw net.Conn, br *bufio.Reader, req *http.Request, cfg *WSConfig) (net.Conn, error) {
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
	if !containsFold(req.Header.Get("Upgrade"), "websocket") {
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

	// 4. 解析真实客户端 IP（支持 Cloudflare CF-Connecting-IP 与 X-Forwarded-For）
	realIP := extractRealClientIP(req)
	var resolvedRemote net.Addr = raw.RemoteAddr()
	if realIP != nil {
		if ta, ok := raw.RemoteAddr().(*net.TCPAddr); ok {
			resolvedRemote = &net.TCPAddr{IP: realIP, Port: ta.Port}
		}
	}

	// 4.5 支持 Xray / v2rayN / sing-box 的 WebSocket 0-RTT Early Data (?ed=2048)
	var earlyData []byte
	var echoProtocol string
	if protoHdr := req.Header.Get("Sec-WebSocket-Protocol"); protoHdr != "" {
		for _, part := range strings.Split(protoHdr, ",") {
			token := strings.TrimSpace(part)
			if token == "" {
				continue
			}
			if decoded, err := base64.RawURLEncoding.DecodeString(token); err == nil && len(decoded) > 0 {
				earlyData = decoded
				echoProtocol = token
				break
			} else if decoded, err := base64.URLEncoding.DecodeString(token); err == nil && len(decoded) > 0 {
				earlyData = decoded
				echoProtocol = token
				break
			} else if decoded, err := base64.StdEncoding.DecodeString(token); err == nil && len(decoded) > 0 {
				earlyData = decoded
				echoProtocol = token
				break
			} else if decoded, err := base64.RawStdEncoding.DecodeString(token); err == nil && len(decoded) > 0 {
				earlyData = decoded
				echoProtocol = token
				break
			}
		}
	}

	// 5. 响应 101 Switching Protocols
	var resp string
	if echoProtocol != "" {
		resp = fmt.Sprintf("HTTP/1.1 101 Switching Protocols\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Accept: %s\r\n"+
			"Sec-WebSocket-Protocol: %s\r\n\r\n", accept, echoProtocol)
	} else {
		resp = fmt.Sprintf("HTTP/1.1 101 Switching Protocols\r\n"+
			"Upgrade: websocket\r\n"+
			"Connection: Upgrade\r\n"+
			"Sec-WebSocket-Accept: %s\r\n\r\n", accept)
	}

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
		readLeft:   earlyData,
		maxLen:     maxLen,
	}, nil
}

// extractRealClientIP 提取 CDN 回源头中的真实访客 IP，杜绝 Cloudflare CDN 节点 IP 触发误封
func extractRealClientIP(req *http.Request) net.IP {
	if cfIP := req.Header.Get("CF-Connecting-IP"); cfIP != "" {
		if ip := net.ParseIP(strings.TrimSpace(cfIP)); ip != nil {
			return ip
		}
	}
	if xri := req.Header.Get("X-Real-IP"); xri != "" {
		if ip := net.ParseIP(strings.TrimSpace(xri)); ip != nil {
			return ip
		}
	}
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
