package main

import (
	"bufio"
	"context"
	"crypto/tls"
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

// ---------- 连接守卫：并发控制、限流与防主动探测封禁（含已认证白名单保护） ----------

type failRec struct {
	count int
	until time.Time
	last  time.Time
}

type Guard struct {
	lim     Limits
	sem     chan struct{}
	mu      sync.Mutex
	conns   map[netip.Addr]int
	fails   map[netip.Addr]*failRec
	trusted map[netip.Addr]time.Time
	stop    chan struct{}
}

func NewGuard(l Limits) *Guard {
	g := &Guard{
		lim:     l,
		sem:     make(chan struct{}, l.MaxConns),
		conns:   make(map[netip.Addr]int),
		fails:   make(map[netip.Addr]*failRec),
		trusted: make(map[netip.Addr]time.Time),
		stop:    make(chan struct{}),
	}
	// 定期清理过期封禁记录与信任白名单
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
				for ip, until := range g.trusted {
					if now.After(until) {
						delete(g.trusted, ip)
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
	if c == nil || c.RemoteAddr() == nil {
		return netip.Addr{}
	}
	if ta, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return ta.AddrPort().Addr().Unmap()
	}
	if ua, ok := c.RemoteAddr().(*net.UDPAddr); ok {
		return netIPToAddr(ua.IP)
	}
	return netip.Addr{}
}

// Acquire 检查全局并发上限、单 IP 限制及黑名单状态
func (g *Guard) Acquire(ip netip.Addr) bool {
	g.mu.Lock()
	now := time.Now()
	until, isTrusted := g.trusted[ip]
	isTrusted = isTrusted && now.Before(until)
	if !isTrusted {
		if f := g.fails[ip]; f != nil && now.Before(f.until) {
			g.mu.Unlock()
			stats.Banned.Add(1)
			return false
		}
	}
	maxPerIP := g.lim.MaxConnsPerIP
	if isTrusted && maxPerIP < 2048 {
		maxPerIP = 2048
	}
	if g.conns[ip] >= maxPerIP {
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

// AuthSuccess 标记某客户端 IP 已成功通过代理认证，2 小时内免于误封并清除历史失败记录
func (g *Guard) AuthSuccess(ip netip.Addr) {
	if !ip.IsValid() || ip.IsLoopback() {
		return
	}
	g.mu.Lock()
	g.trusted[ip] = time.Now().Add(2 * time.Hour)
	delete(g.fails, ip)
	g.mu.Unlock()
}

// Fail 记录一次明确的认证口令错误，达到阈值后自动拉黑（已认证用户 IP 免疫误封）
func (g *Guard) Fail(ip netip.Addr) {
	stats.AuthFail.Add(1)
	if !ip.IsValid() || ip.IsLoopback() {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	if until, ok := g.trusted[ip]; ok && now.Before(until) {
		return
	}
	f := g.fails[ip]
	if f == nil {
		f = &failRec{}
		g.fails[ip] = f
	}
	f.last = now
	f.count++
	if f.count >= g.lim.BanAfterFailures {
		banDur := g.lim.BanDuration.Duration
		if f.count > g.lim.BanAfterFailures {
			mult := f.count - g.lim.BanAfterFailures + 1
			if mult > 6 {
				mult = 6
			}
			banDur = banDur * time.Duration(mult)
		}
		f.until = now.Add(banDur)
		slog.Warn("probing/auth ban applied", "ip", ip, "duration", banDur)
	}
}

// ---------- 智能出站拨号（IPv6 路由自检 + Stale-While-Revalidate DNS 缓存 + SSRF 防护） ----------

type dnsEntry struct {
	ips        []net.IP
	expiresAt  time.Time
	refreshing bool
}

type Outbound struct {
	d            net.Dialer
	blockPrivate bool
	bind         string
	hasIPv6      bool
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
		o.hasIPv6 = ip.Is6()
	} else if probe6, err := net.DialUDP("udp6", nil, &net.UDPAddr{IP: net.ParseIP("2001:4860:4860::8888"), Port: 53}); err == nil {
		// 零流量内核路由表探测：仅当本机真正具备公网全局 IPv6 路由时才启用 AAAA 解析，彻底消灭 AWS EC2 单栈主机 7s IPv6 黑洞卡顿
		localIP := probe6.LocalAddr().(*net.UDPAddr).IP
		_ = probe6.Close()
		if localIP != nil && !localIP.IsLoopback() && !localIP.IsLinkLocalUnicast() && !localIP.IsUnspecified() {
			o.hasIPv6 = true
		}
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

func (o *Outbound) lookupAndCache(ctx context.Context, host string) ([]net.IP, error) {
	netProto := "ip4"
	if o.hasIPv6 {
		netProto = "ip"
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, netProto, host)
	if err != nil {
		o.dnsMu.Lock()
		if cur, exists := o.dnsCache[host]; exists {
			cur.refreshing = false
			o.dnsCache[host] = cur
		}
		o.dnsMu.Unlock()
		return nil, err
	}

	var v4, v6 []net.IP
	for _, ip := range ips {
		if o.blockPrivate && isBlockedIP(ip) {
			continue
		}
		if ip4 := ip.To4(); ip4 != nil {
			v4 = append(v4, ip4)
		} else if o.hasIPv6 {
			v6 = append(v6, ip)
		}
	}
	valid := append(v4, v6...)
	if len(valid) == 0 {
		o.dnsMu.Lock()
		if cur, exists := o.dnsCache[host]; exists {
			cur.refreshing = false
			o.dnsCache[host] = cur
		}
		o.dnsMu.Unlock()
		return nil, errors.New("no routable destination ip available")
	}

	o.dnsMu.Lock()
	o.dnsCache[host] = dnsEntry{
		ips:        valid,
		expiresAt:  time.Now().Add(5 * time.Minute),
		refreshing: false,
	}
	o.dnsMu.Unlock()
	return valid, nil
}

func (o *Outbound) ResolveTarget(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if o.blockPrivate && isBlockedIP(ip) {
			return nil, errors.New("destination blocked by ssrf policy")
		}
		if ip4 := ip.To4(); ip4 != nil {
			return []net.IP{ip4}, nil
		}
		return []net.IP{ip}, nil
	}

	now := time.Now()
	o.dnsMu.RLock()
	e, ok := o.dnsCache[host]
	o.dnsMu.RUnlock()
	if ok {
		if now.Before(e.expiresAt) {
			return e.ips, nil
		}
		// Stale-While-Revalidate: 过期 30 分钟内零等待返回缓存 IP，后台异步刷新
		if now.Sub(e.expiresAt) < 30*time.Minute {
			o.dnsMu.Lock()
			cur, stillOK := o.dnsCache[host]
			needRefresh := stillOK && !cur.refreshing && now.After(cur.expiresAt)
			if needRefresh {
				cur.refreshing = true
				o.dnsCache[host] = cur
			}
			o.dnsMu.Unlock()
			if needRefresh {
				go func(h string) {
					rctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
					defer cancel()
					_, _ = o.lookupAndCache(rctx, h)
				}(host)
			}
			return e.ips, nil
		}
	}

	return o.lookupAndCache(ctx, host)
}

func (o *Outbound) Dial(ctx context.Context, host string, port int) (net.Conn, error) {
	rctx, rcancel := context.WithTimeout(ctx, 3*time.Second)
	ips, err := o.ResolveTarget(rctx, host)
	rcancel()
	if err != nil {
		network := "tcp4"
		if o.hasIPv6 {
			network = "tcp"
		}
		c, dialErr := o.d.DialContext(ctx, network, hostPort(host, port))
		if dialErr == nil {
			enableTCPNoDelay(c)
		}
		return c, dialErr
	}

	var lastErr error
	for i, ip := range ips {
		attemptCtx := ctx
		var cancel context.CancelFunc
		// 多候选 IP 时对前序节点设置 2s 快速故障切换，避免单个黑洞 IP 拖慢首屏
		if i < len(ips)-1 {
			attemptCtx, cancel = context.WithTimeout(ctx, 2*time.Second)
		}
		c, err := o.d.DialContext(attemptCtx, "tcp", hostPort(ip.String(), port))
		if cancel != nil {
			cancel()
		}
		if err == nil {
			enableTCPNoDelay(c)
			return c, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

// ---------- 高性能双向转发管道与缓冲池 ----------

var brPool = sync.Pool{
	New: func() any {
		return bufio.NewReaderSize(nil, 8192)
	},
}

func acquireReader(r io.Reader) *bufio.Reader {
	br := brPool.Get().(*bufio.Reader)
	br.Reset(r)
	return br
}

func releaseReader(br *bufio.Reader) {
	if br != nil {
		br.Reset(nil)
		brPool.Put(br)
	}
}

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

// unwrapTCPConn 仅解包明文透传的 *net.TCPConn 以便利用 Linux splice(2) 零拷贝（绝不穿透 TLS/加密层）
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

// enableTCPNoDelay 穿透外层协议包装，为底层 TCP 套接字开启 TCP_NODELAY 降低首包交互延迟
func enableTCPNoDelay(c net.Conn) {
	for c != nil {
		switch v := c.(type) {
		case *net.TCPConn:
			_ = v.SetNoDelay(true)
			return
		case *tls.Conn:
			c = v.NetConn()
		case *bufConn:
			c = v.Conn
		case *wsConn:
			c = v.Conn
		case *ssConn:
			c = v.Conn
		default:
			return
		}
	}
}

// relay 在 a 与 b 两个连接之间安全、高性能双向转发
// 严格等待双侧读写协程完全退出后才返回，确保外层 defer releaseReader(br) 绝不发生并发数据竞争
func relay(a, b net.Conn, idle time.Duration) {
	defer a.Close()
	defer b.Close()

	enableTCPNoDelay(a)
	enableTCPNoDelay(b)

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
		// 零拷贝通道：仅当双方均为明文底层 TCP 套接字且无预读残留时，触发 Linux splice(2)
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
		// 任一侧异常中断时立即唤醒并终止另一侧阻塞的读写，等待双协程全部安全退出后再释放调用栈资源
		_ = a.SetDeadline(time.Now())
		_ = b.SetDeadline(time.Now())
		_ = a.Close()
		_ = b.Close()
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
