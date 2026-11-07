package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/apernet/quic-go"
)

func main() {
	cfgPath := flag.String("c", "config.json", "config file path")
	check := flag.Bool("t", false, "test config syntax and exit")
	sub := flag.Bool("sub", false, "generate client configs (sing-box, Clash.Meta, v2rayN) and exit")
	host := flag.String("host", "", "public IP or domain name for client configs generation")
	keygen := flag.Bool("keygen", false, "generate Reality X25519 keypair and short ID and exit")
	flag.Parse()

	if *keygen {
		priv, pub, err := GenerateX25519Keypair()
		if err != nil {
			fmt.Fprintln(os.Stderr, "keygen error:", err)
			os.Exit(1)
		}
		sid := GenerateShortID()
		fmt.Printf("PrivateKey: %s\nPublicKey:  %s\nShortID:    %s\n", priv, pub, sid)
		return
	}

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		os.Exit(1)
	}
	if *check {
		fmt.Println("config ok")
		return
	}

	// 导出全平台客户端订阅与节点配置
	if *sub {
		pubHost := *host
		if pubHost == "" {
			pubHost = "YOUR_SERVER_IP"
		}
		fmt.Print(GenerateClientConfigs(cfg, ExportOptions{PublicHost: pubHost}))
		return
	}

	lv := slog.LevelInfo
	_ = lv.UnmarshalText([]byte(cfg.LogLevel))
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lv})))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, cfg); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg *Config) error {
	out, err := NewOutbound(cfg.Outbound)
	if err != nil {
		return fmt.Errorf("outbound init: %w", err)
	}
	guard := NewGuard(cfg.Limits)
	defer guard.Close()
	udpMgr := NewUDPManager(out, cfg.Limits.IdleTimeout.Duration)
	defer udpMgr.Close()

	// 收集外部 listener 占用的端口，严禁回落服务与核心监听器端口冲突导致 bind 失败
	listenerPorts := make(map[string]bool)
	for _, lc := range cfg.Listeners {
		if _, p, err := net.SplitHostPort(lc.Listen); err == nil {
			listenerPorts[p] = true
		}
	}

	// 启动内置反探测伪装站点（针对配置了本地 127.0.0.1 等本地回落地址的监听器）
	startedFallbacks := make(map[string]bool)
	for _, lc := range cfg.Listeners {
		var addrs []string
		if lc.Fallback != "" {
			addrs = append(addrs, lc.Fallback)
		}
		if lc.Hy2 != nil && lc.Hy2.Masquerade != "" {
			addrs = append(addrs, lc.Hy2.Masquerade)
		}
		for _, addr := range addrs {
			h, p, err := net.SplitHostPort(addr)
			if err == nil && (h == "127.0.0.1" || h == "localhost" || h == "::1") && !listenerPorts[p] {
				if !startedFallbacks[addr] {
					startedFallbacks[addr] = true
					if err := StartEmbeddedFallback(ctx, addr); err != nil {
						slog.Warn("cannot start embedded fallback (maybe in use by external web server)", "addr", addr, "err", err)
					}
				}
			}
		}
	}

	var wg sync.WaitGroup
	var servers []*Server
	var udpListeners []*net.UDPConn
	var quicListeners []*quic.Listener

	// 全局证书探测：供未显式配置 TLS 的 WebSocket 监听器（如 8080 端口）自动提供 TLS(WSS) + 明文(WS) 双栈兼容
	var globalWSTLSCfg *tls.Config
	if gTLS := findGlobalTLS(cfg); gTLS != nil {
		if cl, err := newCertLoader(gTLS.Cert, gTLS.Key); err == nil {
			globalWSTLSCfg = &tls.Config{
				GetCertificate: cl.get,
				MinVersion:     tls.VersionTLS12,
				NextProtos:     []string{"http/1.1"},
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				},
			}
		}
	}

	for _, lc := range cfg.Listeners {
		// Hysteria 2 基于 QUIC/UDP，独立处理监听器初始化
		if lc.Type == "hysteria2" || lc.Type == "hy2" {
			hy2Ln, err := StartHy2Listener(ctx, lc, out, guard, cfg.Limits, udpMgr, &wg)
			if err != nil {
				return fmt.Errorf("hy2 %s: %w", lc.Listen, err)
			}
			quicListeners = append(quicListeners, hy2Ln)
			continue
		}

		var coreHandler Handler
		switch lc.Type {
		case "socks5":
			coreHandler = (&socks5Handler{users: lc.Users, out: out, guard: guard, lim: cfg.Limits, udpMgr: udpMgr}).handle

		case "http":
			coreHandler = (&httpHandler{users: lc.Users, out: out, guard: guard, lim: cfg.Limits}).handle

		case "shadowsocks":
			sh := newSSHandler(lc, out, guard, cfg.Limits, udpMgr)
			coreHandler = sh.handle
			if lc.IsUDP() {
				uAddr, err := net.ResolveUDPAddr("udp", lc.Listen)
				if err != nil {
					return fmt.Errorf("resolve ss udp %s: %w", lc.Listen, err)
				}
				uLn, err := net.ListenUDP("udp", uAddr)
				if err != nil {
					return fmt.Errorf("listen ss udp %s: %w", lc.Listen, err)
				}
				udpListeners = append(udpListeners, uLn)
				slog.Info("listening udp", "type", "shadowsocks", "addr", uLn.LocalAddr())
				go sh.ServeUDP(ctx, uLn)
			}

		case "trojan":
			// 当 Trojan 挂载在 WebSocket 传输层后时，TLS 终止由外层负责，避免内层重复 Handshake
			trojanLC := lc
			if lc.Transport != nil && lc.Transport.Type == "ws" {
				trojanLC.TLS = nil
			}
			th, err := newTrojanHandler(trojanLC, out, guard, cfg.Limits, udpMgr)
			if err != nil {
				return fmt.Errorf("trojan %s: %w", lc.Listen, err)
			}
			coreHandler = th.handle

		case "vless":
			vh, err := newVLESSHandler(lc, out, guard, cfg.Limits, udpMgr)
			if err != nil {
				return fmt.Errorf("vless %s: %w", lc.Listen, err)
			}
			coreHandler = vh.handle
		}

		// 传输层中介包装：如果配置了 WebSocket（例如 Cloudflare CDN 代理中转或直连 WSS）
		if lc.Transport != nil && lc.Transport.Type == "ws" {
			upstreamHandler := coreHandler
			wsCfg := lc.Transport.WS
			coreHandler = func(ctx context.Context, c net.Conn) {
				_ = c.SetReadDeadline(time.Now().Add(cfg.Limits.HandshakeTimeout.Duration))
				br := acquireReader(c)
				defer releaseReader(br)
				wsConn, err := UpgradeWebSocket(c, br, wsCfg)
				if err != nil {
					return
				}
				_ = c.SetReadDeadline(time.Time{})
				upstreamHandler(ctx, wsConn)
			}
		}

		// 传输层外层包装：Reality、标准 TLS 或 WebSocket 双栈自适应 (WSS + WS)
		var h Handler
		if lc.Reality != nil {
			var tlsCfg *tls.Config
			if lc.TLS != nil {
				cl, err := newCertLoader(lc.TLS.Cert, lc.TLS.Key)
				if err == nil {
					tlsCfg = &tls.Config{GetCertificate: cl.get, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
				}
			}
			rh, err := newRealityHandler(lc.Reality, coreHandler, guard, cfg.Limits, tlsCfg)
			if err != nil {
				return fmt.Errorf("%s reality %s: %w", lc.Type, lc.Listen, err)
			}
			h = rh.handle
		} else if lc.TLS != nil && (lc.Type == "vless" || (lc.Transport != nil && lc.Transport.Type == "ws")) {
			cl, err := newCertLoader(lc.TLS.Cert, lc.TLS.Key)
			if err != nil {
				return fmt.Errorf("%s tls %s: %w", lc.Type, lc.Listen, err)
			}
			tlsCfg := &tls.Config{
				GetCertificate: cl.get,
				MinVersion:     tls.VersionTLS12,
				NextProtos:     []string{"http/1.1"},
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				},
			}
			inner := coreHandler
			h = func(ctx context.Context, c net.Conn) {
				_ = c.SetDeadline(time.Now().Add(cfg.Limits.HandshakeTimeout.Duration))
				tc := tls.Server(c, tlsCfg)
				if err := tc.Handshake(); err != nil {
					return
				}
				_ = tc.SetDeadline(time.Time{})
				inner(ctx, tc)
			}
		} else if lc.Transport != nil && lc.Transport.Type == "ws" && globalWSTLSCfg != nil {
			// 智能双栈嗅探：首字节 0x16 自动执行 TLS (WSS，满足 Xray 26.10.31 强制加密及 Cloudflare Full)，明文 HTTP 直接走 WS (兼容 Cloudflare Flexible)
			inner := coreHandler
			wsTLS := globalWSTLSCfg
			h = func(ctx context.Context, c net.Conn) {
				_ = c.SetReadDeadline(time.Now().Add(cfg.Limits.HandshakeTimeout.Duration))
				br := acquireReader(c)
				defer releaseReader(br)
				b, err := br.Peek(1)
				if err != nil {
					return
				}
				_ = c.SetReadDeadline(time.Time{})
				wrapped := &bufConn{Conn: c, r: br}
				if b[0] == 0x16 {
					tc := tls.Server(wrapped, wsTLS)
					_ = tc.SetDeadline(time.Now().Add(cfg.Limits.HandshakeTimeout.Duration))
					if err := tc.Handshake(); err != nil {
						return
					}
					_ = tc.SetDeadline(time.Time{})
					inner(ctx, tc)
					return
				}
				inner(ctx, wrapped)
			}
		} else {
			h = coreHandler
		}

		lcfg := net.ListenConfig{KeepAlive: 30 * time.Second}
		ln, err := lcfg.Listen(ctx, "tcp", lc.Listen)
		if err != nil {
			slog.Error("listen tcp failed, skipping listener", "type", lc.Type, "addr", lc.Listen, "err", err)
			continue
		}
		slog.Info("listening tcp", "type", lc.Type, "addr", ln.Addr())
		servers = append(servers, &Server{name: lc.Type + "@" + lc.Listen, ln: ln, guard: guard, h: h, wg: &wg})
	}

	for _, s := range servers {
		go s.Serve(ctx)
	}

	// 监控指标与订阅接口
	var ms *http.Server
	if cfg.MetricsListen != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]int64{
				"active":       stats.Active.Load(),
				"total":        stats.Total.Load(),
				"auth_fail":    stats.AuthFail.Load(),
				"banned_drops": stats.Banned.Load(),
				"rejected":     stats.Rejected.Load(),
				"bytes_up":     stats.BytesUp.Load(),
				"bytes_down":   stats.BytesDown.Load(),
				"udp_sessions": udpMgr.activeSess.Load(),
			})
		})
		mux.HandleFunc("/sub", func(w http.ResponseWriter, r *http.Request) {
			if cfg.SubToken != "" {
				token := r.URL.Query().Get("token")
				if token == "" {
					token = r.Header.Get("X-Sub-Token")
				}
				if token != cfg.SubToken {
					http.Error(w, "Unauthorized: invalid sub token", http.StatusUnauthorized)
					return
				}
			}
			pubHost := r.URL.Query().Get("host")
			if pubHost == "" {
				pubHost = r.Host
				if h, _, err := net.SplitHostPort(pubHost); err == nil {
					pubHost = h
				}
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte(GenerateClientConfigs(cfg, ExportOptions{PublicHost: pubHost})))
		})
		ms = &http.Server{Addr: cfg.MetricsListen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		go func() {
			if err := ms.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("metrics server", "err", err)
			}
		}()
	}

	<-ctx.Done()
	slog.Info("shutting down: closing listeners, draining active connections", "grace", cfg.Limits.ShutdownGrace.Duration)
	for _, s := range servers {
		_ = s.ln.Close()
	}
	for _, u := range udpListeners {
		_ = u.Close()
	}
	for _, qln := range quicListeners {
		_ = qln.Close()
	}
	if ms != nil {
		_ = ms.Close()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		slog.Info("all connections drained cleanly")
	case <-time.After(cfg.Limits.ShutdownGrace.Duration):
		slog.Warn("shutdown grace period expired, exiting", "remaining_active", stats.Active.Load())
	}
	return nil
}
