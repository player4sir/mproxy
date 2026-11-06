package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// ExportOptions 客户端导出选项
type ExportOptions struct {
	PublicHost string // 外部可访问的公网 IP 或域名，默认使用自动侦测或配置文件中的监听地址
}

// GenerateClientConfigs 根据当前 mproxy 的 Listener 配置，自动生成全平台客户端配置与通用分享链接
func GenerateClientConfigs(cfg *Config, opt ExportOptions) string {
	var sb strings.Builder

	host := opt.PublicHost
	if host == "" {
		host = "YOUR_SERVER_IP"
	}

	sb.WriteString("====================================================================\n")
	sb.WriteString("            mproxy 全平台客户端配置与订阅链接生成器\n")
	sb.WriteString(" 支持客户端: sing-box, Clash.Meta (Mihomo), v2rayN, Shadowrocket, v2rayNG\n")
	sb.WriteString("====================================================================\n\n")

	sb.WriteString("----------------- [1] 一键导入通用节点链接 (Universal Links) -----------------\n")
	sb.WriteString("可直接复制并在 v2rayN, Shadowrocket, v2rayNG, Clash Verge 中“从剪贴板导入”:\n\n")

	var clashProxies []map[string]any
	var singboxOutbounds []map[string]any

	for i, l := range cfg.Listeners {
		_, pStr, _ := net.SplitHostPort(l.Listen)
		port, _ := strconv.Atoi(pStr)

		switch l.Type {
		case "vless":
			uuid := "a5e18239-6523-446f-b258-2e06180632a7"
			if len(l.Passwords) > 0 {
				uuid = l.Passwords[0]
			}
			for _, u := range l.Users {
				uuid = u
				break
			}

			if l.Reality != nil {
				sni := "www.microsoft.com"
				if len(l.Reality.ServerNames) > 0 {
					sni = l.Reality.ServerNames[0]
				}
				sid := ""
				if len(l.Reality.ShortIDs) > 0 {
					sid = l.Reality.ShortIDs[0]
				}

				// VLESS + Reality 标准 URI
				link := fmt.Sprintf("vless://%s@%s:%d?encryption=none&flow=xtls-rprx-vision&security=reality&sni=%s&fp=chrome&sid=%s&type=tcp#mproxy-VLESS-Reality",
					uuid, host, port, sni, sid)
				sb.WriteString(fmt.Sprintf("[VLESS Reality 节点]\n%s\n\n", link))

				// Clash.Meta 节点对象
				clashProxies = append(clashProxies, map[string]any{
					"name":               fmt.Sprintf("VLESS-Reality-%d", i+1),
					"type":               "vless",
					"server":             host,
					"port":               port,
					"uuid":               uuid,
					"network":            "tcp",
					"tls":                true,
					"udp":                true,
					"flow":               "xtls-rprx-vision",
					"servername":         sni,
					"client-fingerprint": "chrome",
					"reality-opts": map[string]any{
						"public-key": "REPLACE_WITH_REALITY_PUBKEY",
						"short-id":   sid,
					},
				})

				// sing-box 节点对象
				singboxOutbounds = append(singboxOutbounds, map[string]any{
					"type":        "vless",
					"tag":         fmt.Sprintf("vless-reality-%d", i+1),
					"server":      host,
					"server_port": port,
					"uuid":        uuid,
					"flow":        "xtls-rprx-vision",
					"tls": map[string]any{
						"enabled":     true,
						"server_name": sni,
						"utls": map[string]any{
							"enabled":     true,
							"fingerprint": "chrome",
						},
						"reality": map[string]any{
							"enabled":    true,
							"public_key": "REPLACE_WITH_REALITY_PUBKEY",
							"short_id":   sid,
						},
					},
				})

			} else if l.Transport != nil && l.Transport.Type == "ws" {
				// VLESS + WebSocket (CDN 优选与中转专用)
				domain := host
				wsPath := l.Transport.WS.Path
				if wsPath == "" {
					wsPath = "/vless-ws"
				}
				link := fmt.Sprintf("vless://%s@%s:%d?encryption=none&security=tls&sni=%s&type=ws&host=%s&path=%s#mproxy-VLESS-WS-CDN",
					uuid, host, port, domain, domain, url.QueryEscape(wsPath))
				sb.WriteString(fmt.Sprintf("[VLESS WebSocket CDN 节点]\n%s\n\n", link))

				clashProxies = append(clashProxies, map[string]any{
					"name":       fmt.Sprintf("VLESS-WS-CDN-%d", i+1),
					"type":       "vless",
					"server":     host,
					"port":       port,
					"uuid":       uuid,
					"network":    "ws",
					"tls":        true,
					"udp":        true,
					"servername": domain,
					"ws-opts": map[string]any{
						"path": wsPath,
						"headers": map[string]any{
							"Host": domain,
						},
					},
				})

				singboxOutbounds = append(singboxOutbounds, map[string]any{
					"type":        "vless",
					"tag":         fmt.Sprintf("vless-ws-cdn-%d", i+1),
					"server":      host,
					"server_port": port,
					"uuid":        uuid,
					"tls": map[string]any{
						"enabled":     true,
						"server_name": domain,
					},
					"transport": map[string]any{
						"type": "ws",
						"path": wsPath,
						"headers": map[string]any{
							"Host": domain,
						},
					},
				})
			}

		case "hysteria2", "hy2":
			pw := l.Password
			if l.Hy2 != nil && l.Hy2.Password != "" {
				pw = l.Hy2.Password
			}
			if pw == "" && len(l.Passwords) > 0 {
				pw = l.Passwords[0]
			}
			link := fmt.Sprintf("hysteria2://%s@%s:%d?sni=%s&insecure=0#mproxy-Hysteria2", pw, host, port, host)
			sb.WriteString(fmt.Sprintf("[Hysteria 2 节点]\n%s\n\n", link))

			clashProxies = append(clashProxies, map[string]any{
				"name":             fmt.Sprintf("Hy2-Node-%d", i+1),
				"type":             "hysteria2",
				"server":           host,
				"port":             port,
				"password":         pw,
				"sni":              host,
				"skip-cert-verify": false,
			})

			singboxOutbounds = append(singboxOutbounds, map[string]any{
				"type":        "hysteria2",
				"tag":         fmt.Sprintf("hy2-node-%d", i+1),
				"server":      host,
				"server_port": port,
				"password":    pw,
				"tls": map[string]any{
					"enabled":     true,
					"server_name": host,
				},
			})

		case "trojan":
			pw := "CHANGE_ME"
			if len(l.Passwords) > 0 {
				pw = l.Passwords[0]
			}
			link := fmt.Sprintf("trojan://%s@%s:%d?security=tls&sni=%s#mproxy-Trojan", pw, host, port, host)
			sb.WriteString(fmt.Sprintf("[Trojan 节点]\n%s\n\n", link))

			clashProxies = append(clashProxies, map[string]any{
				"name":       fmt.Sprintf("Trojan-Node-%d", i+1),
				"type":       "trojan",
				"server":     host,
				"port":       port,
				"password":   pw,
				"sni":        host,
				"udp":        true,
			})

			singboxOutbounds = append(singboxOutbounds, map[string]any{
				"type":        "trojan",
				"tag":         fmt.Sprintf("trojan-node-%d", i+1),
				"server":      host,
				"server_port": port,
				"password":    pw,
				"tls": map[string]any{
					"enabled":     true,
					"server_name": host,
				},
			})

		case "shadowsocks":
			encoded := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", l.Method, l.Password)))
			link := fmt.Sprintf("ss://%s@%s:%d#mproxy-Shadowsocks", encoded, host, port)
			sb.WriteString(fmt.Sprintf("[Shadowsocks 节点]\n%s\n\n", link))

			clashProxies = append(clashProxies, map[string]any{
				"name":     fmt.Sprintf("SS-Node-%d", i+1),
				"type":     "ss",
				"server":   host,
				"port":     port,
				"cipher":   l.Method,
				"password": l.Password,
				"udp":      true,
			})

			singboxOutbounds = append(singboxOutbounds, map[string]any{
				"type":        "shadowsocks",
				"tag":         fmt.Sprintf("ss-node-%d", i+1),
				"server":      host,
				"server_port": port,
				"method":      l.Method,
				"password":    l.Password,
			})
		}
	}

	sb.WriteString("----------------- [2] Clash.Meta (Mihomo) 配置片段 -----------------\n")
	sb.WriteString("可直接复制填入 Clash Verge / Clash Nyanpasu / Stash 的 proxies 字段:\n\n")
	clashJSON, _ := json.MarshalIndent(map[string]any{"proxies": clashProxies}, "", "  ")
	sb.WriteString(string(clashJSON))
	sb.WriteString("\n\n")

	sb.WriteString("----------------- [3] sing-box 客户端配置片段 -----------------\n")
	sb.WriteString("可直接复制填入 sing-box (iOS/Android/Windows/macOS) 的 outbounds 数组中:\n\n")
	singboxJSON, _ := json.MarshalIndent(singboxOutbounds, "", "  ")
	sb.WriteString(string(singboxJSON))
	sb.WriteString("\n\n")

	sb.WriteString("----------------- [4] Cloudflare CDN 中转部署指引 -----------------\n")
	sb.WriteString("1. 在 Cloudflare DNS 解析中将您的域名开启【小黄云】(Proxied) 代理加速。\n")
	sb.WriteString("2. 在 Cloudflare 控制台 -> SSL/TLS 设置为【Full (完全)】或【Strict】。\n")
	sb.WriteString("3. 在 Cloudflare -> Network (网络) 设置中，开启【WebSockets】和【gRPC】开关。\n")
	sb.WriteString("4. 在 mproxy 的 config.json 中，为 vless 或 trojan 配置 transport.type = \"ws\"，并指定 path: \"/vless-ws\"。\n")
	sb.WriteString("5. 客户端连接地址填写 Cloudflare CDN 优选 IP (如 104.16.x.x) 或 CDN 域名，Host / SNI 填写您的真实域名即可实现被封 IP 的极速复活与流量伪装！\n\n")

	return sb.String()
}
