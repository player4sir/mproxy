package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

const embeddedHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Edge Node Gateway | Status Online</title>
    <style>
        :root { --bg: #0f172a; --card: #1e293b; --text: #f8fafc; --accent: #38bdf8; --green: #22c55e; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 0; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
        .container { background: var(--card); border-radius: 12px; padding: 2.5rem; max-width: 580px; width: 90%; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.5); border: 1px solid #334155; }
        .header { display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #334155; padding-bottom: 1.25rem; margin-bottom: 1.5rem; }
        .title { font-size: 1.25rem; font-weight: 600; color: var(--text); }
        .badge { background: rgba(34,197,94,0.15); color: var(--green); padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; display: flex; align-items: center; gap: 0.35rem; }
        .badge::before { content: ""; width: 6px; height: 6px; background: var(--green); border-radius: 50%; display: inline-block; }
        p { color: #94a3b8; font-size: 0.95rem; line-height: 1.6; margin: 0 0 1.25rem; }
        .metrics { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; margin-top: 1.5rem; }
        .metric-card { background: rgba(15,23,42,0.6); padding: 1rem; border-radius: 8px; border: 1px solid #334155; text-align: center; }
        .metric-val { font-size: 1.25rem; font-weight: 700; color: var(--accent); margin-bottom: 0.25rem; }
        .metric-lbl { font-size: 0.75rem; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; }
        .footer { margin-top: 2rem; text-align: center; font-size: 0.8rem; color: #475569; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="title">Enterprise API Gateway</div>
            <div class="badge">Operational</div>
        </div>
        <p>Welcome to Edge Cluster Node. The distributed routing layer, load balancer, and TLS termination services are currently active and functioning normally.</p>
        <div class="metrics">
            <div class="metric-card"><div class="metric-val">99.99%</div><div class="metric-lbl">Uptime</div></div>
            <div class="metric-card"><div class="metric-val">&lt; 1 ms</div><div class="metric-lbl">Latency</div></div>
            <div class="metric-card"><div class="metric-val">TLS 1.3</div><div class="metric-lbl">Security</div></div>
        </div>
        <div class="footer">&copy; 2026 Cloud Networking Infrastructure Services. All rights reserved.</div>
    </div>
</body>
</html>`

// proxyProtocolListener 包装 net.Listener，用于透明剥离回落站点的 PROXY protocol v1 头
type proxyProtocolListener struct {
	net.Listener
}

func (l *proxyProtocolListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	// 预读并剥离可能存在的 PROXY protocol v1 头: "PROXY TCP4/TCP6 ...\r\n"
	br := bufio.NewReader(c)
	head, _ := br.Peek(6)
	if string(head) == "PROXY " {
		_, _ = br.ReadString('\n')
	}
	return &bufConn{Conn: c, r: br}, nil
}

// StartEmbeddedFallback 启动内置开箱即用的轻量级反探测伪装站点
func StartEmbeddedFallback(ctx context.Context, listenAddr string) error {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Server", "nginx/1.24.0")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(embeddedHTML))
	})

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	wrappedLn := &proxyProtocolListener{Listener: ln}
	slog.Info("embedded anti-probe fallback web server running", "addr", listenAddr)

	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()

	go func() {
		if err := srv.Serve(wrappedLn); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			slog.Debug("embedded fallback server exit", "err", err)
		}
	}()

	return nil
}
