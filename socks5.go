package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

type socks5Handler struct {
	users  map[string]string
	out    *Outbound
	guard  *Guard
	lim    Limits
	udpMgr *UDPManager
}

func (h *socks5Handler) handle(ctx context.Context, c net.Conn) {
	ip := addrOf(c)
	_ = c.SetDeadline(time.Now().Add(h.lim.HandshakeTimeout.Duration))

	// 1. 协商认证方式
	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return
	}
	if hdr[0] != 5 {
		h.guard.Fail(ip)
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	want := byte(0x00)
	if len(h.users) > 0 {
		want = 0x02
	}
	ok := false
	for _, m := range methods {
		if m == want {
			ok = true
			break
		}
	}
	if !ok {
		_, _ = c.Write([]byte{5, 0xFF})
		h.guard.Fail(ip)
		return
	}
	if _, err := c.Write([]byte{5, want}); err != nil {
		return
	}

	// 2. 执行认证
	if want == 0x02 {
		if !h.auth(c) {
			h.guard.Fail(ip)
			return
		}
		h.guard.AuthSuccess(ip)
	}

	// 3. 读取请求头
	var req [3]byte
	if _, err := io.ReadFull(c, req[:]); err != nil || req[0] != 5 {
		return
	}
	host, port, err := readAddr(c)
	if err != nil {
		replySocks5(c, 0x08, "0.0.0.0", 0)
		return
	}

	cmd := req[1]
	switch cmd {
	case 0x01: // CONNECT (TCP)
		dctx, cancel := context.WithTimeout(ctx, h.lim.HandshakeTimeout.Duration)
		r, err := h.out.Dial(dctx, host, port)
		cancel()
		if err != nil {
			replySocks5(c, socksErrCode(err), "0.0.0.0", 0)
			return
		}
		// 响应成功：返回本地绑定的地址（0.0.0.0:0）
		replySocks5(c, 0x00, "0.0.0.0", 0)
		_ = c.SetDeadline(time.Time{})
		relay(c, r, h.lim.IdleTimeout.Duration)

	case 0x03: // UDP ASSOCIATE
		h.handleUDPAssociate(ctx, c)

	default:
		// 0x02 BIND 等不支持的命令
		replySocks5(c, 0x07, "0.0.0.0", 0)
	}
}

func (h *socks5Handler) handleUDPAssociate(ctx context.Context, c net.Conn) {
	// 为该客户端分配 UDP 中继套接字
	localTCPAddr := c.LocalAddr().(*net.TCPAddr)
	udpLn, err := net.ListenUDP("udp", &net.UDPAddr{IP: localTCPAddr.IP, Port: 0})
	if err != nil {
		replySocks5(c, 0x01, "0.0.0.0", 0)
		return
	}
	defer udpLn.Close()

	assignedPort := udpLn.LocalAddr().(*net.UDPAddr).Port
	bindIP := localTCPAddr.IP.String()
	if localTCPAddr.IP.IsUnspecified() {
		if remoteTCP, ok := c.RemoteAddr().(*net.TCPAddr); ok {
			if probeConn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: remoteTCP.IP, Port: 1}); err == nil {
				bindIP = probeConn.LocalAddr().(*net.UDPAddr).IP.String()
				probeConn.Close()
			} else {
				bindIP = "127.0.0.1"
			}
		} else {
			bindIP = "127.0.0.1"
		}
	}
	replySocks5(c, 0x00, bindIP, assignedPort)
	_ = c.SetDeadline(time.Time{})

	var clientUDPAddr *net.UDPAddr
	var clientMu sync.RWMutex

	defer func() {
		clientMu.RLock()
		target := clientUDPAddr
		clientMu.RUnlock()
		if target != nil {
			h.udpMgr.RemoveSession(fmt.Sprintf("socks5:%s", target.String()))
		}
	}()

	// 启动 UDP 读包循环
	go func() {
		bp := udpBufPool.Get().(*[]byte)
		defer udpBufPool.Put(bp)
		buf := *bp

		remoteTCP, _ := c.RemoteAddr().(*net.TCPAddr)

		for {
			_ = udpLn.SetReadDeadline(time.Now().Add(h.lim.IdleTimeout.Duration))
			n, rAddr, err := udpLn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n < 4 {
				continue
			}
			// 校验 UDP 源 IP 是否与建立 TCP 控制连接的客户端一致，防止未授权劫持
			if remoteTCP != nil && !rAddr.IP.Equal(remoteTCP.IP) {
				continue
			}
			// 校验 SOCKS5 UDP 头: RSV(2B)=0, FRAG(1B)=0
			if buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
				continue // 不支持分片
			}

			clientMu.Lock()
			clientUDPAddr = rAddr
			clientMu.Unlock()

			tHost, tPort, offset, err := parseAddrBytes(buf[3:n])
			if err != nil {
				continue
			}
			payload := buf[3+offset : n]

			clientKey := fmt.Sprintf("socks5:%s", rAddr.String())
			_ = h.udpMgr.SendPacket(clientKey, tHost, tPort, payload, func(respHost string, respPort int, respPayload []byte) error {
				clientMu.RLock()
				target := clientUDPAddr
				clientMu.RUnlock()
				if target == nil {
					return nil
				}
				// 封装 SOCKS5 UDP 响应头
				header, err := writeAddr([]byte{0x00, 0x00, 0x00}, respHost, respPort)
				if err != nil {
					return err
				}
				packet := append(header, respPayload...)
				_, err = udpLn.WriteToUDP(packet, target)
				return err
			})
		}
	}()

	// 维持 TCP 存活，当客户端关闭 TCP 连接时终止 UDP 中继
	drainBuf := make([]byte, 128)
	for {
		_ = c.SetReadDeadline(time.Now().Add(h.lim.IdleTimeout.Duration))
		if _, err := c.Read(drainBuf); err != nil {
			break
		}
	}
}

func (h *socks5Handler) auth(c net.Conn) bool {
	var v [1]byte
	if _, err := io.ReadFull(c, v[:]); err != nil || v[0] != 1 {
		return false
	}
	readStr := func() (string, bool) {
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return "", false
		}
		b := make([]byte, l[0])
		_, err := io.ReadFull(c, b)
		return string(b), err == nil
	}
	u, ok1 := readStr()
	p, ok2 := readStr()
	if !ok1 || !ok2 {
		return false
	}
	pw, found := h.users[u]
	good := found && subtle.ConstantTimeCompare([]byte(pw), []byte(p)) == 1
	if good {
		_, _ = c.Write([]byte{1, 0})
	} else {
		_, _ = c.Write([]byte{1, 1})
	}
	return good
}

func replySocks5(c net.Conn, code byte, bndHost string, bndPort int) {
	resp, err := writeAddr([]byte{5, code, 0}, bndHost, bndPort)
	if err != nil {
		_, _ = c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	_, _ = c.Write(resp)
}

func socksErrCode(err error) byte {
	var ne net.Error
	switch {
	case errors.As(err, &ne) && ne.Timeout():
		return 0x04
	case errors.Is(err, context.DeadlineExceeded):
		return 0x04
	}
	s := err.Error()
	if strings.Contains(s, "refused") {
		return 0x05
	}
	if strings.Contains(s, "blocked by ssrf") {
		return 0x02
	}
	if strings.Contains(s, "unreachable") {
		return 0x03
	}
	return 0x01
}
