package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type Duration struct{ time.Duration }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration must be a string like \"10s\": %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

type Config struct {
	LogLevel      string           `json:"log_level"`
	MetricsListen string           `json:"metrics_listen"` // 监控指标监听地址（建议 127.0.0.1:9090）
	SubToken      string           `json:"sub_token"`      // 订阅与监控接口访问安全令牌（可选）
	Limits        Limits           `json:"limits"`
	Outbound      OutboundConfig   `json:"outbound"`
	Listeners     []ListenerConfig `json:"listeners"`
}

type Limits struct {
	MaxConns         int      `json:"max_conns"`
	MaxConnsPerIP    int      `json:"max_conns_per_ip"`
	IdleTimeout      Duration `json:"idle_timeout"`
	HandshakeTimeout Duration `json:"handshake_timeout"`
	BanAfterFailures int      `json:"ban_after_failures"`
	BanDuration      Duration `json:"ban_duration"`
	ShutdownGrace    Duration `json:"shutdown_grace"`
}

type OutboundConfig struct {
	DialTimeout  Duration `json:"dial_timeout"`
	BlockPrivate bool     `json:"block_private"` // 禁止经代理访问内网/回环地址（防 SSRF）
	Bind         string   `json:"bind"`          // 可选：出站绑定的本地源 IP
}

type TLSConfig struct {
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

type TransportConfig struct {
	Type string    `json:"type"` // tcp | ws (专用于 Cloudflare CDN 反向代理中转)
	WS   *WSConfig `json:"ws"`   // WebSocket 详细参数配置
}

type ListenerConfig struct {
	Type   string `json:"type"`   // vless | hysteria2 | trojan | shadowsocks | socks5 | http
	Listen string `json:"listen"` // 监听地址，例如 "0.0.0.0:443" 或 "0.0.0.0:80"
	UDP    *bool  `json:"udp"`    // 是否开启 UDP 中继支持（默认开启）

	Transport             *TransportConfig  `json:"transport"`              // 传输层配置（tcp 或 ws CDN 中转）
	TLS                   *TLSConfig        `json:"tls"`                    // TLS 证书配置
	Reality               *RealityConfig    `json:"reality"`                // Reality 强抗封锁伪装配置
	Hy2                   *Hy2Config        `json:"hy2"`                    // Hysteria 2 协议配置
	Passwords             []string          `json:"passwords"`              // trojan 密码 / vless UUID 列表 / hy2 密码
	Fallback              string            `json:"fallback"`               // 探测回落网站地址（如 127.0.0.1:8080）
	FallbackProxyProtocol bool              `json:"fallback_proxy_protocol"`// 向回落站点发送 PROXY protocol v1 头
	Method                string            `json:"method"`                 // shadowsocks 加密算法: aes-128-gcm | aes-256-gcm
	Password              string            `json:"password"`               // shadowsocks / hysteria2 密码
	Users                 map[string]string `json:"users"`                  // socks5 / http 用户名密码，或 vless 用户->UUID
}

func (l *ListenerConfig) IsUDP() bool {
	if l.UDP == nil {
		return true
	}
	return *l.UDP
}

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := json.NewDecoder(bytesReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	setDefaults(&c)
	return &c, c.validate()
}

func setDefaults(c *Config) {
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	l := &c.Limits
	if l.MaxConns == 0 {
		l.MaxConns = 20000
	}
	if l.MaxConnsPerIP == 0 {
		l.MaxConnsPerIP = 512
	}
	if l.IdleTimeout.Duration == 0 {
		l.IdleTimeout.Duration = 5 * time.Minute
	}
	if l.HandshakeTimeout.Duration == 0 {
		l.HandshakeTimeout.Duration = 10 * time.Second
	}
	if l.BanAfterFailures == 0 {
		l.BanAfterFailures = 8
	}
	if l.BanDuration.Duration == 0 {
		l.BanDuration.Duration = 10 * time.Minute
	}
	if l.ShutdownGrace.Duration == 0 {
		l.ShutdownGrace.Duration = 30 * time.Second
	}
	if c.Outbound.DialTimeout.Duration == 0 {
		c.Outbound.DialTimeout.Duration = 8 * time.Second
	}
	for i := range c.Listeners {
		if c.Listeners[i].UDP == nil {
			enable := true
			c.Listeners[i].UDP = &enable
		}
	}
}

func (c *Config) validate() error {
	if len(c.Listeners) == 0 {
		return fmt.Errorf("no listeners configured")
	}
	for i, l := range c.Listeners {
		if l.Listen == "" {
			return fmt.Errorf("listeners[%d]: listen is required", i)
		}
		switch l.Type {
		case "vless":
			if len(l.Passwords) == 0 && len(l.Users) == 0 {
				return fmt.Errorf("listeners[%d]: vless requires passwords or users (UUIDs)", i)
			}
			// 当使用 WebSocket CDN 中转（例如挂载在 Nginx/CDN 之后，由 CDN 提供 TLS 卸载）时，TLS 并非强制项
			isWS := l.Transport != nil && l.Transport.Type == "ws"
			if !isWS && l.Reality == nil && (l.TLS == nil || l.TLS.Cert == "" || l.TLS.Key == "") {
				return fmt.Errorf("listeners[%d]: vless requires tls, reality, or websocket transport configuration", i)
			}
		case "hysteria2", "hy2":
			if l.TLS == nil || l.TLS.Cert == "" || l.TLS.Key == "" {
				return fmt.Errorf("listeners[%d]: hysteria2 requires tls (cert and key)", i)
			}
			pw := l.Password
			if l.Hy2 != nil && l.Hy2.Password != "" {
				pw = l.Hy2.Password
			}
			if pw == "" && len(l.Passwords) == 0 {
				return fmt.Errorf("listeners[%d]: hysteria2 requires password", i)
			}
		case "trojan":
			isWS := l.Transport != nil && l.Transport.Type == "ws"
			if !isWS && l.Reality == nil && (l.TLS == nil || l.TLS.Cert == "" || l.TLS.Key == "") {
				return fmt.Errorf("listeners[%d]: trojan requires tls (cert & key), reality, or ws transport", i)
			}
			if len(l.Passwords) == 0 {
				return fmt.Errorf("listeners[%d]: trojan requires passwords", i)
			}
		case "shadowsocks":
			if l.Password == "" {
				return fmt.Errorf("listeners[%d]: shadowsocks requires password", i)
			}
			if _, ok := ssMethods[l.Method]; !ok {
				return fmt.Errorf("listeners[%d]: unsupported method %q", i, l.Method)
			}
		case "socks5", "http":
		default:
			return fmt.Errorf("listeners[%d]: unknown type %q", i, l.Type)
		}
	}
	return nil
}
