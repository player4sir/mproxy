package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"sync"
	"time"
)

var ssMethods = map[string]int{"aes-128-gcm": 16, "aes-256-gcm": 32}

const (
	ssTag      = 16
	ssMaxChunk = 0x3FFF
)

var errSSAuth = errors.New("shadowsocks: auth failed")

// ssMasterKey 使用 EVP_BytesToKey (MD5) 派生主密钥，兼容标准 SS 客户端
func ssMasterKey(password string, n int) []byte {
	var out, prev []byte
	for len(out) < n {
		h := md5.New()
		h.Write(prev)
		h.Write([]byte(password))
		prev = h.Sum(nil)
		out = append(out, prev...)
	}
	return out[:n]
}

func hkdfSHA1(secret, salt, info []byte, n int) []byte {
	ext := hmac.New(sha1.New, salt)
	ext.Write(secret)
	prk := ext.Sum(nil)
	var out, prev []byte
	for i := byte(1); len(out) < n; i++ {
		m := hmac.New(sha1.New, prk)
		m.Write(prev)
		m.Write(info)
		m.Write([]byte{i})
		prev = m.Sum(nil)
		out = append(out, prev...)
	}
	return out[:n]
}

func newGCM(key, salt []byte) cipher.AEAD {
	sub := hkdfSHA1(key, salt, []byte("ss-subkey"), len(key))
	b, _ := aes.NewCipher(sub)
	g, _ := cipher.NewGCM(b)
	return g
}

func incNonce(n []byte) {
	for i := range n {
		n[i]++
		if n[i] != 0 {
			return
		}
	}
}

// replayFilter 双代内存哈希表轮转，防止重放探测攻击
type replayFilter struct {
	mu        sync.Mutex
	cur, prev map[string]struct{}
	max       int
}

func newReplayFilter(max int) *replayFilter {
	return &replayFilter{
		cur:  make(map[string]struct{}),
		prev: make(map[string]struct{}),
		max:  max,
	}
}

func (f *replayFilter) seen(salt []byte) bool {
	k := string(salt)
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.cur[k]; ok {
		return true
	}
	if _, ok := f.prev[k]; ok {
		return true
	}
	if len(f.cur) >= f.max {
		f.prev, f.cur = f.cur, make(map[string]struct{}, f.max)
	}
	f.cur[k] = struct{}{}
	return false
}

// ssConn 服务端 Shadowsocks TCP AEAD 连接包装
type ssConn struct {
	net.Conn
	key    []byte
	replay *replayFilter

	dec    cipher.AEAD
	dnonce [12]byte
	rbuf   []byte
	left   []byte
	enc    cipher.AEAD
	enonce [12]byte
	wbuf   []byte
}

func newSSConn(c net.Conn, key []byte, rf *replayFilter) *ssConn {
	return &ssConn{
		Conn:   c,
		key:    key,
		replay: rf,
		rbuf:   make([]byte, ssMaxChunk+ssTag),
		wbuf:   make([]byte, len(key)+2+ssTag+ssMaxChunk+ssTag),
	}
}

func (c *ssConn) Read(p []byte) (int, error) {
	if len(c.left) > 0 {
		n := copy(p, c.left)
		c.left = c.left[n:]
		return n, nil
	}
	if c.dec == nil {
		salt := make([]byte, len(c.key))
		if _, err := io.ReadFull(c.Conn, salt); err != nil {
			return 0, err
		}
		if c.replay.seen(salt) {
			return 0, errSSAuth
		}
		c.dec = newGCM(c.key, salt)
	}
	lb := c.rbuf[:2+ssTag]
	if _, err := io.ReadFull(c.Conn, lb); err != nil {
		return 0, err
	}
	l, err := c.dec.Open(lb[:0], c.dnonce[:], lb, nil)
	if err != nil {
		return 0, errSSAuth
	}
	incNonce(c.dnonce[:])
	n := int(binary.BigEndian.Uint16(l)) & ssMaxChunk
	if n == 0 {
		return 0, errSSAuth
	}
	pb := c.rbuf[:n+ssTag]
	if _, err := io.ReadFull(c.Conn, pb); err != nil {
		return 0, err
	}
	plain, err := c.dec.Open(pb[:0], c.dnonce[:], pb, nil)
	if err != nil {
		return 0, errSSAuth
	}
	incNonce(c.dnonce[:])
	m := copy(p, plain)
	c.left = plain[m:]
	return m, nil
}

func (c *ssConn) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		out := c.wbuf[:0]
		if c.enc == nil {
			salt := make([]byte, len(c.key))
			if _, err := rand.Read(salt); err != nil {
				return total, err
			}
			out = append(out, salt...)
			c.enc = newGCM(c.key, salt)
		}
		n := len(p)
		if n > ssMaxChunk {
			n = ssMaxChunk
		}
		var lb [2]byte
		binary.BigEndian.PutUint16(lb[:], uint16(n))
		out = c.enc.Seal(out, c.enonce[:], lb[:], nil)
		incNonce(c.enonce[:])
		out = c.enc.Seal(out, c.enonce[:], p[:n], nil)
		incNonce(c.enonce[:])
		if _, err := c.Conn.Write(out); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

func (c *ssConn) CloseWrite() error {
	closeWrite(c.Conn)
	return nil
}

type ssHandler struct {
	key    []byte
	replay *replayFilter
	out    *Outbound
	guard  *Guard
	lim    Limits
	udpMgr *UDPManager
}

func newSSHandler(lc ListenerConfig, out *Outbound, g *Guard, lim Limits, udpMgr *UDPManager) *ssHandler {
	return &ssHandler{
		key:    ssMasterKey(lc.Password, ssMethods[lc.Method]),
		replay: newReplayFilter(65536),
		out:    out,
		guard:  g,
		lim:    lim,
		udpMgr: udpMgr,
	}
}

func (h *ssHandler) handle(ctx context.Context, raw net.Conn) {
	ip := addrOf(raw)
	_ = raw.SetDeadline(time.Now().Add(h.lim.HandshakeTimeout.Duration))
	sc := newSSConn(raw, h.key, h.replay)
	host, port, err := readAddr(sc)
	if err != nil {
		if errors.Is(err, errSSAuth) || errors.Is(err, errBadAddr) {
			// 认证失败时引入随机化延时吞噬，杜绝固定时长定时指纹特征
			h.guard.Fail(ip)
			randDelay, _ := rand.Int(rand.Reader, big.NewInt(6))
			_ = raw.SetDeadline(time.Now().Add(time.Duration(3+randDelay.Int64()) * time.Second))
			_, _ = io.Copy(io.Discard, raw)
		}
		return
	}
	h.guard.AuthSuccess(ip)
	dctx, cancel := context.WithTimeout(ctx, h.lim.HandshakeTimeout.Duration)
	up, err := h.out.Dial(dctx, host, port)
	cancel()
	if err != nil {
		return
	}
	_ = raw.SetDeadline(time.Time{})
	relay(sc, up, h.lim.IdleTimeout.Duration)
}

// ServeUDP 开启 Shadowsocks 原生 AEAD UDP 服务监听
// 数据包结构: [Salt (key_len bytes)] [Encrypted Payload (SOCKS5 Addr + Data)]
func (h *ssHandler) ServeUDP(ctx context.Context, ln *net.UDPConn) {
	bp := udpBufPool.Get().(*[]byte)
	defer udpBufPool.Put(bp)
	buf := *bp

	keyLen := len(h.key)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, clientAddr, err := ln.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		clientIP := netIPToAddr(clientAddr.IP)
		if !h.guard.Acquire(clientIP) {
			continue
		}

		if n <= keyLen+ssTag {
			h.guard.Release(clientIP)
			continue
		}

		salt := buf[:keyLen]
		if h.replay.seen(salt) {
			h.guard.Release(clientIP)
			continue // 重放攻击防范
		}

		aead := newGCM(h.key, salt)
		var nonce [12]byte
		// 严格使用 buf[keyLen:keyLen] (即 ciphertext[:0]) 原地解密，避免与前置 salt 产生非对齐内存重叠导致 Go cipher.AEAD panic
		plain, err := aead.Open(buf[keyLen:keyLen], nonce[:], buf[keyLen:n], nil)
		if err != nil {
			h.guard.Fail(clientIP)
			h.guard.Release(clientIP)
			continue
		}
		h.guard.AuthSuccess(clientIP)
		h.guard.Release(clientIP)

		tHost, tPort, offset, err := parseAddrBytes(plain)
		if err != nil {
			continue
		}
		payload := make([]byte, len(plain[offset:]))
		copy(payload, plain[offset:])
		cAddr := *clientAddr

		func() {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("panic in ss udp handler", "panic", r)
				}
			}()
			clientKey := fmt.Sprintf("ss:%s", cAddr.String())
			_ = h.udpMgr.SendPacket(clientKey, tHost, tPort, payload, func(respHost string, respPort int, respPayload []byte) error {
				respAddrHeader, err := writeAddr(nil, respHost, respPort)
				if err != nil {
					return err
				}
				respPlain := append(respAddrHeader, respPayload...)

				respSalt := make([]byte, keyLen)
				if _, err := rand.Read(respSalt); err != nil {
					return err
				}
				respAead := newGCM(h.key, respSalt)
				var respNonce [12]byte

				ciphertext := respAead.Seal(respSalt, respNonce[:], respPlain, nil)
				_, err = ln.WriteToUDP(ciphertext, &cAddr)
				return err
			})
		}()
	}
}
