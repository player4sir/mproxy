package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ---------- 统计监控 ----------

type Stats struct {
	Active, Total, AuthFail, Banned, Rejected atomic.Int64
	BytesUp, BytesDown                        atomic.Int64
	UDPSessions                               atomic.Int64
}

var stats Stats

// ---------- 连接守卫：并发控制、限流与防主动探测封禁 ----------

type failRec struct {
	count int
	until time.Time
	last  time.Time
}

type Guard struct {
	lim   Limits
	sem   chan struct{}
	mu    sync.Mutex
	conns map[netip.Addr]int
	fails map[netip.Addr]*failRec
	stop  chan struct{}
}

func NewGuard(l Limits) *Guard {
	g := &Guard{
		lim:   l,
		sem:   make(chan struct{}, l.MaxConns),
		conns: make(map[netip.Addr]int),
		fails: make(map[netip.Addr]*failRec),
		stop:  make(chan struct{}),
	}
	// 定期清理过期封禁记录
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-g.stop:
				return
			case <-ticker.C:
				g.mu.Lock()
				now := time.Now()
				for ip, f := range g.fails {
					if now.After(f.until) && now.Sub(f.last) > 15*time.Minute {
						delete(g.fails, ip)
					}
				}
				g.mu.Unlock()
			}
		}
	}()
	return g
}

func (g *Guard) Close() {
	select {
	case <-g.stop:
	default:
		close(g.stop)
	}
}

func addrOf(c net.Conn) netip.Addr {
	if ta, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return ta.AddrPort().Addr().Unmap()
	}
	return netip.Addr{}
}

// Acquire 检查全局并发上限、单 IP 限制及黑名单状态
func (g *Guard) Acquire(ip netip.Addr) bool {
	g.mu.Lock()
	if f := g.fails[ip]; f != nil && time.Now().Before(f.until) {
		g.mu.Unlock()
		stats.Banned.Add(1)
		return false
	}
	if g.conns[ip] >= g.lim.MaxConnsPerIP {
		g.mu.Unlock()
		stats.Rejected.Add(1)
		return false
	}
	select {
	case g.sem <- struct{}{}:
	default:
		g.mu.Unlock()
		stats.Rejected.Add(1)
		return false
	}
	g.conns[ip]++
	g.mu.Unlock()
	return true
}

func (g *Guard) Release(ip netip.Addr) {
	g.mu.Lock()
	if g.conns[ip]--; g.conns[ip] <= 0 {
		delete(g.conns, ip)
	}
	g.mu.Unlock()
	<-g.sem
}

// Fail 记录一次认证失败或异常嗅探探针，达到阈值后自动拉黑
func (g *Guard) Fail(ip netip.Addr) {
	stats.AuthFail.Add(1)
	if !ip.IsValid() || ip.IsLoopback() {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	f := g.fails[ip]
	if f == nil {
		f = &failRec{}
		g.fails[ip] = f
	}
	f.last = time.Now()
	f.count++
	if f.count >= g.lim.BanAfterFailures {
		// 指数退避：每次封禁时间递增，严防长时间低频探测
		banDur := g.lim.BanDuration.Duration
		if f.count > g.lim.BanAfterFailures {
			mult := f.count - g.lim.BanAfterFailures + 1
			if mult > 6 {
				mult = 6
			}
			banDur = banDur * time.Duration(mult)
		}
		f.until = time.Now().Add(banDur)
		slog.Warn("probing/auth ban applied", "ip", ip, "duration", banDur)
	}
}

// ---------- 智能出站拨号（带 DNS 缓存与 SSRF 防护） ----------

type dnsEntry struct {
	ips       []net.IP
	expiresAt time.Time
}

type Outbound struct {
	d            net.Dialer
	blockPrivate bool
	bind         string
	dnsMu        sync.RWMutex
	dnsCache     map[string]dnsEntry
}

func NewOutbound(c OutboundConfig) (*Outbound, error) {
	o := &Outbound{
		blockPrivate: c.BlockPrivate,
		bind:         c.Bind,
		dnsCache:     make(map[string]dnsEntry),
	}
	o.d = net.Dialer{
		Timeout:       c.DialTimeout.Duration,
		KeepAlive:     30 * time.Second,
		FallbackDelay: 250 * time.Millisecond,
	}
	if c.Bind != "" {
		ip, err := netip.ParseAddr(c.Bind)
		if err != nil {
			return nil, fmt.Errorf("outbound.bind: %w", err)
		}
		o.d.LocalAddr = &net.TCPAddr{IP: ip.AsSlice()}
	}

	if c.BlockPrivate {
		// connect 前深度校验目标地址，杜绝 DNS Rebinding / SSRF
		o.d.Control = func(_, address string, _ syscall.RawConn) error {
			h, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip, err := netip.ParseAddr(h)
			if err != nil {
				return err
			}
			ip = ip.Unmap()
			if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
				ip.IsMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() {
				return errors.New("destination blocked by ssrf policy")
			}
			return nil
		}
	}
	return o, nil
}

func isBlockedIP(ip net.IP) bool {
	if nip, err := netip.ParseAddr(ip.String()); err == nil {
		nip = nip.Unmap()
		return nip.IsLoopback() || nip.IsPrivate() || nip.IsLinkLocalUnicast() ||
			nip.IsLinkLocalMulticast() || nip.IsMulticast() || nip.IsUnspecified() ||
			nip.IsInterfaceLocalMulticast()
	}
	return true
}

func (o *Outbound) ResolveTarget(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if o.blockPrivate && isBlockedIP(ip) {
			return nil, errors.New("destination blocked by ssrf policy")
		}
		return []net.IP{ip}, nil
	}

	o.dnsMu.RLock()
	e, ok := o.dnsCache[host]
	o.dnsMu.RUnlock()
	if ok && time.Now().Before(e.expiresAt) {
		return e.ips, nil
	}

	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}

	var valid []net.IP
	for _, ip := range ips {
		if o.blockPrivate && isBlockedIP(ip) {
			continue
		}
		valid = append(valid, ip)
	}
	if len(valid) == 0 {
		return nil, errors.New("destination blocked by ssrf policy")
	}

	o.dnsMu.Lock()
	o.dnsCache[host] = dnsEntry{
		ips:       valid,
		expiresAt: time.Now().Add(2 * time.Minute),
	}
	o.dnsMu.Unlock()
	return valid, nil
}

func (o *Outbound) Dial(ctx context.Context, host string, port int) (net.Conn, error) {
	return o.d.DialContext(ctx, "tcp", hostPort(host, port))
}

// ---------- 高性能双向转发管道 ----------

var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32<<10) // 32KB 优化单流吞吐与 cache line
		return &b
	},
}

type closeWriter interface {
	CloseWrite() error
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

// bufConn 缓冲连接，支持未读缓冲与直接透传
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

func (c *bufConn) CloseWrite() error {
	closeWrite(c.Conn)
	return nil
}

// unwrapTCPConn 尝试解包到底层 *net.TCPConn 以便利用 Linux splice(2) 零拷贝
func unwrapTCPConn(c net.Conn) (*net.TCPConn, *bufio.Reader) {
	if bc, ok := c.(*bufConn); ok {
		if tc, ok := bc.Conn.(*net.TCPConn); ok {
			return tc, bc.r
		}
	}
	if tc, ok := c.(*net.TCPConn); ok {
		return tc, nil
	}
	return nil, nil
}

// relay 在 a 与 b 两个连接之间高性能双向转发
// 核心优化：
// 1. 批量超时刷新（Batch Deadline Updates）：减少 99.9% 的 SetDeadline 系统调用与 timer 锁争用
// 2. 尝试解包底层 TCPConn 触发内核零拷贝 splice
// 3. sync.Pool 32KB 缓冲复用
func relay(a, b net.Conn, idle time.Duration) {
	defer a.Close()
	defer b.Close()

	// 开启 TCP_NODELAY 降低交互延迟
	if ta, _ := unwrapTCPConn(a); ta != nil {
		_ = ta.SetNoDelay(true)
	}
	if tb, _ := unwrapTCPConn(b); tb != nil {
		_ = tb.SetNoDelay(true)
	}

	done := make(chan error, 2)

	cp := func(dst, src net.Conn, ctr *atomic.Int64) {
		// 先清空 src 可能存在的 bufio 预读缓存
		if bc, ok := src.(*bufConn); ok && bc.r != nil && bc.r.Buffered() > 0 {
			buffered := bc.r.Buffered()
			head, _ := bc.r.Peek(buffered)
			if len(head) > 0 {
				_ = dst.SetWriteDeadline(time.Now().Add(idle))
				if _, werr := dst.Write(head); werr != nil {
					done <- werr
					return
				}
				ctr.Add(int64(len(head)))
				_, _ = bc.r.Discard(len(head))
			}
		}

		rawSrc, r := unwrapTCPConn(src)
		rawDst, _ := unwrapTCPConn(dst)
		// 零拷贝通道：当双方均为底层 TCP 套接字且已无预读残留时，触发 Linux splice(2) 直接内核管道转发
		if rawSrc != nil && rawDst != nil && (r == nil || r.Buffered() == 0) {
			_ = rawSrc.SetReadDeadline(time.Time{})
			_ = rawDst.SetWriteDeadline(time.Time{})
			n, copyErr := io.Copy(rawDst, rawSrc)
			ctr.Add(n)
			if copyErr == nil {
				closeWrite(dst)
			}
			done <- copyErr
			return
		}

		bp := bufPool.Get().(*[]byte)
		defer bufPool.Put(bp)
		buf := *bp

		var lastUpdate time.Time
		interval := idle / 4
		if interval > 15*time.Second {
			interval = 15 * time.Second
		}
		if interval < time.Second {
			interval = time.Second
		}

		var err error
		for {
			now := time.Now()
			if now.Sub(lastUpdate) >= interval {
				_ = src.SetReadDeadline(now.Add(idle))
				_ = dst.SetWriteDeadline(now.Add(idle))
				lastUpdate = now
			}

			n, rerr := src.Read(buf)
			if n > 0 {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					err = werr
					break
				}
				ctr.Add(int64(n))
			}
			if rerr != nil {
				if !errors.Is(rerr, io.EOF) {
					err = rerr
				}
				break
			}
		}
		if err == nil {
			closeWrite(dst)
		}
		done <- err
	}

	go cp(b, a, &stats.BytesUp)
	go cp(a, b, &stats.BytesDown)

	if err := <-done; err != nil {
		return
	}
	<-done
}

// ---------- 通用 Listener 服务循环 ----------

type Handler func(ctx context.Context, c net.Conn)

type Server struct {
	name  string
	ln    net.Listener
	guard *Guard
	h     Handler
	wg    *sync.WaitGroup
}

func (s *Server) Serve(ctx context.Context) {
	var delay time.Duration
	for {
		c, err := s.ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			if delay == 0 {
				delay = 5 * time.Millisecond
			} else if delay *= 2; delay > time.Second {
				delay = time.Second
			}
			slog.Warn("accept error", "listener", s.name, "err", err, "retry_in", delay)
			time.Sleep(delay)
			continue
		}
		delay = 0
		ip := addrOf(c)
		if !s.guard.Acquire(ip) {
			_ = c.Close()
			continue
		}
		stats.Active.Add(1)
		stats.Total.Add(1)
		s.wg.Add(1)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("panic in handler", "listener", s.name, "panic", r)
				}
				_ = c.Close()
				stats.Active.Add(-1)
				s.guard.Release(ip)
				s.wg.Done()
			}()
			s.h(ctx, c)
		}()
	}
}
