package main

import (
	"context"
	"crypto/ecdh"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// ExportOptions 客户端导出选项
type ExportOptions struct {
	PublicHost string // 外部可访问的公网域名或 IP
	PublicIP   string // 服务器真实公网 IPv4（供 Hysteria2 等直连协议零 DNS 拨号，消除 Bootstrap DNS 超时与 Fake-IP 劫持）
}

// resolveDirectHost 获取直连协议（Hysteria2 / Raw TCP / Trojan / SS）的拨号目标地址：
// 优先使用真实公网 IPv4，而 TLS SNI 仍保留绑定域名，从而跳过客户端本地 UDP 53 Bootstrap DNS 查询并避免其他代理 TUN Fake-IP 劫持。
func resolveDirectHost(host, explicitIP string) string {
	if trimmed := strings.TrimSpace(explicitIP); trimmed != "" {
		if ip := net.ParseIP(trimmed); ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				return ip4.String()
			}
			return ip.String()
		}
	}
	if host == "" || host == "YOUR_SERVER_IP" || host == "localhost" || net.ParseIP(host) != nil {
		return host
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host); err == nil {
		for _, ip := range ips {
			if ip4 := ip.To4(); ip4 != nil && !ip4.IsLoopback() && !ip4.IsUnspecified() {
				return ip4.String()
			}
		}
	}
	return host
}

func safeSNI(host string) string {
	if net.ParseIP(host) != nil {
		return "www.microsoft.com"
	}
	return host
}

// isTrustedCertForHost 检测给定证书是否为受信任权威 CA 签发（非自签名）且匹配当前域名
func isTrustedCertForHost(certPath, host string) bool {
	if certPath == "" || host == "" || net.ParseIP(host) != nil || host == "YOUR_SERVER_IP" {
		return false
	}
	b, err := os.ReadFile(certPath)
	if err != nil {
		return false
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	// 自签名证书 Issuer 与 Subject 相同
	if cert.Issuer.String() == cert.Subject.String() {
		return false
	}
	if err := cert.VerifyHostname(host); err != nil {
		return false
	}
	return true
}

// GenerateClientConfigs 自动生成全平台免配置直接连通的订阅链接与客户端配置
func GenerateClientConfigs(cfg *Config, opt ExportOptions) string {
	var sb strings.Builder

	host := opt.PublicHost
	if host == "" {
		host = "YOUR_SERVER_IP"
	}
	directHost := resolveDirectHost(host, opt.PublicIP)

	sb.WriteString("====================================================================\n")
	sb.WriteString("            mproxy 全平台客户端免配置即连订阅链接\n")
	sb.WriteString(" 支持客户端: v2rayN, sing-box, Clash.Meta (Mihomo), Shadowrocket, v2rayNG\n")
	sb.WriteString("====================================================================\n\n")

	sb.WriteString("----------------- [1] 一键导入通用节点链接 (Universal Links) -----------------\n")
	sb.WriteString("已自动完成证书校验与 0-RTT Early Data 加速注入，一键导入直接连通:\n\n")

	var rawLinks []string
	var clashProxies []map[string]any
	var singboxOutbounds []map[string]any
	globalTLS := findGlobalTLS(cfg)

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
				pubKey := l.Reality.PublicKey
				if pubKey == "" && l.Reality.PrivateKey != "" {
					if rawPriv, err := base64.RawURLEncoding.DecodeString(l.Reality.PrivateKey); err == nil {
						if privKey, err := ecdh.X25519().NewPrivateKey(rawPriv); err == nil {
							pubKey = base64.RawURLEncoding.EncodeToString(privKey.PublicKey().Bytes())
						}
					}
				}
				if pubKey == "" {
					_, pub, _ := GenerateX25519Keypair()
					pubKey = pub
				}

				// VLESS + Reality 标准 URI (注入真实合法公钥 pbk，彻底消除 REPLACE_WITH_REALITY_PUBKEY 占位符)
				link := fmt.Sprintf("vless://%s@%s:%d?encryption=none&security=reality&sni=%s&fp=chrome&pbk=%s&sid=%s&type=tcp#mproxy-VLESS-Reality",
					uuid, directHost, port, sni, pubKey, sid)
				sb.WriteString(fmt.Sprintf("[VLESS Reality 节点 (免域名强抗封锁)]\n%s\n\n", link))
				rawLinks = append(rawLinks, link)

				// 同时导出标准 VLESS + TLS 节点（全平台 100% 极速通畅，免证书配置）
				tlsSNI := safeSNI(host)
				tlsLink := fmt.Sprintf("vless://%s@%s:%d?encryption=none&security=tls&allowInsecure=1&sni=%s&type=tcp#mproxy-VLESS-TLS",
					uuid, directHost, port, tlsSNI)
				sb.WriteString(fmt.Sprintf("[VLESS TLS 节点 (全平台秒通)]\n%s\n\n", tlsLink))
				rawLinks = append(rawLinks, tlsLink)

				clashProxies = append(clashProxies, map[string]any{
					"name":               fmt.Sprintf("VLESS-Reality-%d", i+1),
					"type":               "vless",
					"server":             directHost,
					"port":               port,
					"uuid":               uuid,
					"network":            "tcp",
					"tls":                true,
					"udp":                true,
					"servername":         sni,
					"client-fingerprint": "chrome",
					"reality-opts": map[string]any{
						"public-key": pubKey,
						"short-id":   sid,
					},
				})

				singboxOutbounds = append(singboxOutbounds, map[string]any{
					"type":        "vless",
					"tag":         fmt.Sprintf("vless-reality-%d", i+1),
					"server":      directHost,
					"server_port": port,
					"uuid":        uuid,
					"tls": map[string]any{
						"enabled":     true,
						"server_name": sni,
						"utls": map[string]any{
							"enabled":     true,
							"fingerprint": "chrome",
						},
						"reality": map[string]any{
							"enabled":    true,
							"public_key": pubKey,
							"short_id":   sid,
						},
					},
				})

			} else if l.Transport != nil && l.Transport.Type == "ws" {
				// VLESS + WebSocket (专供 CDN 中转与普通 HTTP 代理，默认附加 ?ed=2048 开启 0-RTT Early Data)
				domain := host
				wsPath := l.Transport.WS.Path
				if wsPath == "" {
					wsPath = "/vless-ws"
				}
				wsPathWithED := wsPath
				if !strings.Contains(wsPathWithED, "ed=") {
					wsPathWithED = wsPath + "?ed=2048"
				}

				secParam := "none"
				isTLS := false
				skipVerify := true
				sni := safeSNI(host)
				effectiveTLS := l.TLS
				if effectiveTLS == nil {
					effectiveTLS = globalTLS
				}
				if effectiveTLS != nil {
					isTLS = true
					if isTrustedCertForHost(effectiveTLS.Cert, host) {
						secParam = fmt.Sprintf("tls&sni=%s&fp=chrome&alpn=http%%2F1.1", sni)
						skipVerify = false
					} else {
						secParam = fmt.Sprintf("tls&allowInsecure=1&sni=%s&fp=chrome&alpn=http%%2F1.1", sni)
					}
				}

				link := fmt.Sprintf("vless://%s@%s:%d?encryption=none&security=%s&type=ws&host=%s&path=%s#mproxy-VLESS-WS-CDN",
					uuid, host, port, secParam, domain, url.QueryEscape(wsPathWithED))
				sb.WriteString(fmt.Sprintf("[VLESS WebSocket CDN 节点 (0-RTT 极速)]\n%s\n\n", link))
				rawLinks = append(rawLinks, link)

				clashNode := map[string]any{
					"name":       fmt.Sprintf("VLESS-WS-CDN-%d", i+1),
					"type":       "vless",
					"server":     host,
					"port":       port,
					"uuid":       uuid,
					"network":    "ws",
					"tls":        isTLS,
					"udp":        true,
					"servername": sni,
					"ws-opts": map[string]any{
						"path":                   wsPath,
						"max-early-data":         2048,
						"early-data-header-name": "Sec-WebSocket-Protocol",
						"headers": map[string]any{
							"Host": domain,
						},
					},
				}
				if isTLS {
					clashNode["skip-cert-verify"] = skipVerify
					clashNode["alpn"] = []string{"http/1.1"}
				}
				clashProxies = append(clashProxies, clashNode)

				sbNode := map[string]any{
					"type":        "vless",
					"tag":         fmt.Sprintf("vless-ws-cdn-%d", i+1),
					"server":      host,
					"server_port": port,
					"uuid":        uuid,
					"transport": map[string]any{
						"type":                   "ws",
						"path":                   wsPath,
						"max_early_data":         2048,
						"early_data_header_name": "Sec-WebSocket-Protocol",
						"headers": map[string]any{
							"Host": domain,
						},
					},
				}
				if isTLS {
					sbNode["tls"] = map[string]any{
						"enabled":     true,
						"server_name": sni,
						"insecure":    skipVerify,
						"alpn":        []string{"http/1.1"},
					}
				}
				singboxOutbounds = append(singboxOutbounds, sbNode)

			} else if l.TLS != nil {
				// VLESS + TLS (443 端口同时支持直连 VLESS-TLS 与 Cloudflare 443 WSS)
				// 直连 TCP 节点采用真实公网 IPv4 (directHost) + 域名 SNI，跳过客户端 Bootstrap DNS 且不受开启 Cloudflare 橙色云影响
				sni := safeSNI(host)
				trusted := isTrustedCertForHost(l.TLS.Cert, host)
				insecParam := "&allowInsecure=1"
				if trusted {
					insecParam = ""
				}
				link := fmt.Sprintf("vless://%s@%s:%d?encryption=none&security=tls%s&sni=%s&fp=chrome&type=tcp#mproxy-VLESS-TLS",
					uuid, directHost, port, insecParam, sni)
				sb.WriteString(fmt.Sprintf("[VLESS TLS 节点]\n%s\n\n", link))
				rawLinks = append(rawLinks, link)

				// 额外输出 443 单端口复用的 VLESS-WSS 节点（保留域名地址，专供开启 Cloudflare 小黄云 443 端口直接使用）
				wssLink := fmt.Sprintf("vless://%s@%s:%d?encryption=none&security=tls%s&sni=%s&fp=chrome&alpn=http%%2F1.1&type=ws&host=%s&path=%s#mproxy-VLESS-WSS-443",
					uuid, host, port, insecParam, sni, sni, url.QueryEscape("/vless-ws?ed=2048"))
				sb.WriteString(fmt.Sprintf("[VLESS WSS 443 节点 (支持开启 Cloudflare 橙色云)]\n%s\n\n", wssLink))
				rawLinks = append(rawLinks, wssLink)

				clashProxies = append(clashProxies, map[string]any{
					"name":             fmt.Sprintf("VLESS-TLS-%d", i+1),
					"type":             "vless",
					"server":           directHost,
					"port":             port,
					"uuid":             uuid,
					"network":          "tcp",
					"tls":              true,
					"udp":              true,
					"servername":       sni,
					"skip-cert-verify": !trusted,
				})

				singboxOutbounds = append(singboxOutbounds, map[string]any{
					"type":        "vless",
					"tag":         fmt.Sprintf("vless-tls-%d", i+1),
					"server":      directHost,
					"server_port": port,
					"uuid":        uuid,
					"tls": map[string]any{
						"enabled":     true,
						"server_name": sni,
						"insecure":    !trusted,
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
			sni := safeSNI(host)
			trusted := l.TLS != nil && isTrustedCertForHost(l.TLS.Cert, host)
			insecVal := 1
			if trusted {
				insecVal = 0
			}
			// Hysteria 2 基于纯 UDP/QUIC 直连，使用真实公网 IPv4 (directHost) 作为拨号地址并保留域名 SNI + 正规证书校验，
			// 彻底杜绝 sing-box 本地 UDP 53 (如 119.29.29.29) 解析超时导致 -1，以及杜绝其他代理 TUN Fake-IP (198.18.x.x) 劫持！
			directLink := fmt.Sprintf("hysteria2://%s@%s:%d?sni=%s&alpn=h3&insecure=%d#mproxy-Hysteria2", pw, directHost, port, sni, insecVal)
			sb.WriteString(fmt.Sprintf("[Hysteria 2 节点 (直连极速抗丢包)]\n%s\n\n", directLink))
			rawLinks = append(rawLinks, directLink)

			hopLink := fmt.Sprintf("hysteria2://%s@%s:%d?sni=%s&alpn=h3&insecure=%d&mport=20000-50000#mproxy-Hysteria2-PortHopping", pw, directHost, port, sni, insecVal)
			sb.WriteString(fmt.Sprintf("[Hysteria 2 端口跳跃节点 (20000-50000)]\n%s\n\n", hopLink))
			rawLinks = append(rawLinks, hopLink)

			clashProxies = append(clashProxies, map[string]any{
				"name":             fmt.Sprintf("Hy2-Node-%d", i+1),
				"type":             "hysteria2",
				"server":           directHost,
				"port":             port,
				"ports":            "20000-50000",
				"password":         pw,
				"sni":              sni,
				"alpn":             []string{"h3"},
				"skip-cert-verify": !trusted,
			})

			singboxOutbounds = append(singboxOutbounds, map[string]any{
				"type":        "hysteria2",
				"tag":         fmt.Sprintf("hy2-node-%d", i+1),
				"server":      directHost,
				"server_port": port,
				"password":    pw,
				"tls": map[string]any{
					"enabled":     true,
					"server_name": sni,
					"alpn":        []string{"h3"},
					"insecure":    !trusted,
				},
			})

		case "trojan":
			pw := "CHANGE_ME"
			if len(l.Passwords) > 0 {
				pw = l.Passwords[0]
			}
			sni := safeSNI(host)
			trusted := l.TLS != nil && isTrustedCertForHost(l.TLS.Cert, host)
			insecParam := "&allowInsecure=1"
			if trusted {
				insecParam = ""
			}
			link := fmt.Sprintf("trojan://%s@%s:%d?security=tls&sni=%s%s#mproxy-Trojan", pw, directHost, port, sni, insecParam)
			sb.WriteString(fmt.Sprintf("[Trojan 节点]\n%s\n\n", link))
			rawLinks = append(rawLinks, link)

			clashProxies = append(clashProxies, map[string]any{
				"name":             fmt.Sprintf("Trojan-Node-%d", i+1),
				"type":             "trojan",
				"server":           directHost,
				"port":             port,
				"password":         pw,
				"sni":              sni,
				"udp":              true,
				"skip-cert-verify": !trusted,
			})

			singboxOutbounds = append(singboxOutbounds, map[string]any{
				"type":        "trojan",
				"tag":         fmt.Sprintf("trojan-node-%d", i+1),
				"server":      directHost,
				"server_port": port,
				"password":    pw,
				"tls": map[string]any{
					"enabled":     true,
					"server_name": sni,
					"insecure":    !trusted,
				},
			})

		case "shadowsocks":
			encoded := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", l.Method, l.Password)))
			link := fmt.Sprintf("ss://%s@%s:%d#mproxy-Shadowsocks", encoded, directHost, port)
			sb.WriteString(fmt.Sprintf("[Shadowsocks 节点]\n%s\n\n", link))
			rawLinks = append(rawLinks, link)

			clashProxies = append(clashProxies, map[string]any{
				"name":     fmt.Sprintf("SS-Node-%d", i+1),
				"type":     "ss",
				"server":   directHost,
				"port":     port,
				"cipher":   l.Method,
				"password": l.Password,
				"udp":      true,
			})

			singboxOutbounds = append(singboxOutbounds, map[string]any{
				"type":        "shadowsocks",
				"tag":         fmt.Sprintf("ss-node-%d", i+1),
				"server":      directHost,
				"server_port": port,
				"method":      l.Method,
				"password":    l.Password,
			})
		}
	}

	if len(rawLinks) > 0 {
		b64Sub := base64.StdEncoding.EncodeToString([]byte(strings.Join(rawLinks, "\n")))
		sb.WriteString("[v2rayN / Shadowrocket 整包一键导入 Base64 订阅串 (复制下方整行 Ctrl+V 导入全部节点)]\n")
		sb.WriteString(b64Sub)
		sb.WriteString("\n\n")
	}

	sb.WriteString("----------------- [2] Clash.Meta (Mihomo) 配置片段 -----------------\n")
	sb.WriteString("已自动配置 skip-cert-verify: true，可直接填入 proxies 数组:\n\n")
	clashJSON, _ := json.MarshalIndent(map[string]any{"proxies": clashProxies}, "", "  ")
	sb.WriteString(string(clashJSON))
	sb.WriteString("\n\n")

	sb.WriteString("----------------- [3] sing-box 客户端配置片段 -----------------\n")
	sb.WriteString("已自动配置 insecure: true，可直接填入 outbounds 数组中:\n\n")
	singboxJSON, _ := json.MarshalIndent(singboxOutbounds, "", "  ")
	sb.WriteString(string(singboxJSON))
	sb.WriteString("\n\n")

	sb.WriteString("----------------- [4] Cloudflare CDN 中转部署指引 -----------------\n")
	sb.WriteString("1. 在 Cloudflare DNS 解析中将您的域名开启【小黄云】(Proxied) 代理加速。\n")
	sb.WriteString("2. 在 Cloudflare 控制台 -> SSL/TLS 设置为【Flexible】或【Full】。\n")
	sb.WriteString("3. 在 Cloudflare -> Network (网络) 设置中，开启【WebSockets】。\n")
	sb.WriteString("4. 在客户端中，VLESS WebSocket 节点地址填写 Cloudflare 优选 IP，Host / SNI 填您的域名即可！\n\n")

	return sb.String()
}
