package main

import (
	"bufio"
	"context"
	"crypto/subtle"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type httpHandler struct {
	users map[string]string
	out   *Outbound
	guard *Guard
	lim   Limits
}

func (h *httpHandler) authOK(r *http.Request) bool {
	if len(h.users) == 0 {
		return true
	}
	u, p, ok := parseProxyBasic(r.Header.Get("Proxy-Authorization"))
	if !ok {
		return false
	}
	pw, found := h.users[u]
	return found && subtle.ConstantTimeCompare([]byte(pw), []byte(p)) == 1
}

func parseProxyBasic(v string) (string, string, bool) {
	req := &http.Request{Header: http.Header{"Authorization": {v}}}
	return req.BasicAuth()
}

func (h *httpHandler) handle(ctx context.Context, c net.Conn) {
	ip := addrOf(c)
	_ = c.SetDeadline(time.Now().Add(h.lim.HandshakeTimeout.Duration))
	br := bufio.NewReaderSize(c, 8192)
	req, err := http.ReadRequest(br)
	if err != nil {
		h.guard.Fail(ip)
		return
	}
	if !h.authOK(req) {
		_, _ = c.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		h.guard.Fail(ip)
		return
	}

	var host string
	var port int
	if req.Method == http.MethodConnect {
		hs, ps, err := net.SplitHostPort(req.Host)
		if err != nil {
			httpErr(c, 400)
			return
		}
		host = hs
		port, _ = strconv.Atoi(ps)
	} else {
		if req.URL.Host == "" {
			httpErr(c, 400)
			return
		}
		host = req.URL.Hostname()
		port = 80
		if p := req.URL.Port(); p != "" {
			port, _ = strconv.Atoi(p)
		} else if req.URL.Scheme == "https" {
			port = 443
		}
	}
	if port <= 0 || port > 65535 {
		httpErr(c, 400)
		return
	}

	dctx, cancel := context.WithTimeout(ctx, h.lim.HandshakeTimeout.Duration)
	up, err := h.out.Dial(dctx, host, port)
	cancel()
	if err != nil {
		httpErr(c, 502)
		return
	}
	_ = c.SetDeadline(time.Time{})
	client := &bufConn{Conn: c, r: br}

	if req.Method == http.MethodConnect {
		_, _ = c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		relay(client, up, h.lim.IdleTimeout.Duration)
		return
	}
	// 普通 HTTP 转发：一次性请求，Connection: close 简化状态机
	for k := range req.Header {
		if strings.HasPrefix(k, "Proxy-") {
			req.Header.Del(k)
		}
	}
	req.Header.Set("Connection", "close")
	req.RequestURI = ""
	if err := req.Write(up); err != nil {
		up.Close()
		return
	}
	relay(client, up, h.lim.IdleTimeout.Duration)
}

func httpErr(c net.Conn, code int) {
	_, _ = c.Write([]byte("HTTP/1.1 " + strconv.Itoa(code) + " " + http.StatusText(code) + "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
}
