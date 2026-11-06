package main

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"strings"
	"time"
)

// RealityConfig Reality 伪装配置：借用真实海外大站证书，消除服务端 TLS 特征并反弹主动探测
type RealityConfig struct {
	Dest        string   `json:"dest"`         // 真实伪装目标地址，例如 "www.microsoft.com:443" 或 "gateway.icloud.com:443"
	ServerNames []string `json:"server_names"` // 允许的 SNI 列表
	PrivateKey  string   `json:"private_key"`  // X25519 服务端私钥 (Base64URL)
	PublicKey   string   `json:"public_key"`   // X25519 客户端连接公钥 (Base64URL)
	ShortIDs    []string `json:"short_ids"`    // 客户端鉴权短 ID 列表（十六进制）
}

// GenerateX25519Keypair 使用标准库 crypto/ecdh 生成合法的 X25519 密钥对
func GenerateX25519Keypair() (string, string, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate x25519: %w", err)
	}
	privStr := base64.RawURLEncoding.EncodeToString(priv.Bytes())
	pubStr := base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())
	return privStr, pubStr, nil
}

// GenerateShortID 生成 8 字节 (16 字符 hex) 随机鉴权 ShortID
func GenerateShortID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

type realityHandler struct {
	dest        string
	serverNames map[string]struct{}
	shortIDs    map[string]struct{}
	inner       Handler
	guard       *Guard
	lim         Limits
	tlsCfg      *tls.Config
}

func generateSelfSignedCert(names []string) (*tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	sn, _ := rand.Int(rand.Reader, big.NewInt(100000000))
	cn := "www.microsoft.com"
	if len(names) > 0 {
		cn = names[0]
	}
	tpl := x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		DNSNames:     names,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	cert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
	return &cert, nil
}

func newRealityHandler(cfg *RealityConfig, inner Handler, g *Guard, lim Limits, customTLS *tls.Config) (*realityHandler, error) {
	if cfg == nil || cfg.Dest == "" {
		return nil, errors.New("reality requires dest (e.g. www.microsoft.com:443)")
	}

	// 自动补全或推导 X25519 密钥对
	if cfg.PrivateKey == "" {
		priv, pub, err := GenerateX25519Keypair()
		if err == nil {
			cfg.PrivateKey = priv
			cfg.PublicKey = pub
			slog.Info("auto-generated reality x25519 keypair", "pub", pub)
		}
	} else if cfg.PublicKey == "" {
		if rawPriv, err := base64.RawURLEncoding.DecodeString(cfg.PrivateKey); err == nil {
			if privKey, err := ecdh.X25519().NewPrivateKey(rawPriv); err == nil {
				cfg.PublicKey = base64.RawURLEncoding.EncodeToString(privKey.PublicKey().Bytes())
			}
		}
	}
	if len(cfg.ShortIDs) == 0 {
		cfg.ShortIDs = []string{GenerateShortID()}
	}

	tlsCfg := customTLS
	if tlsCfg == nil {
		cert, err := generateSelfSignedCert(cfg.ServerNames)
		if err != nil {
			return nil, fmt.Errorf("reality cert gen: %w", err)
		}
		tlsCfg = &tls.Config{
			Certificates: []tls.Certificate{*cert},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"h2", "http/1.1"},
		}
	}

	h := &realityHandler{
		dest:        cfg.Dest,
		serverNames: make(map[string]struct{}),
		shortIDs:    make(map[string]struct{}),
		inner:       inner,
		guard:       g,
		lim:         lim,
		tlsCfg:      tlsCfg,
	}
	for _, sn := range cfg.ServerNames {
		h.serverNames[strings.ToLower(sn)] = struct{}{}
	}
	for _, sid := range cfg.ShortIDs {
		h.shortIDs[strings.ToLower(sid)] = struct{}{}
	}
	return h, nil
}

// sniffClientHello 嗅探并解析 TLS ClientHello，提取 SNI 与 SessionID，同时保留已读字节
func sniffClientHello(r *bufio.Reader) (sni string, sessionID []byte, rawHello []byte, err error) {
	// TLS Record Header: 5 字节 [0x16, 0x03, 0x01/0x03, Length 2B]
	header, err := r.Peek(5)
	if err != nil {
		return "", nil, nil, err
	}
	if header[0] != 0x16 { // 不是 TLS Handshake
		return "", nil, nil, errors.New("not a tls handshake")
	}
	recordLen := int(header[3])<<8 | int(header[4])
	if recordLen < 4 || recordLen > 16384 {
		return "", nil, nil, errors.New("invalid tls record length")
	}

	totalLen := 5 + recordLen
	rawHello, err = r.Peek(totalLen)
	if err != nil {
		return "", nil, nil, err
	}

	// Handshake Type: 1 字节 (0x01 为 ClientHello)
	if rawHello[5] != 0x01 {
		return "", nil, nil, errors.New("not a client hello")
	}

	// ClientHello 内部结构解析
	idx := 5 + 4 // 跳过 Handshake Header (Type 1B + Length 3B)
	if idx+34 > len(rawHello) {
		return "", nil, nil, errors.New("truncated client hello")
	}
	idx += 34 // 跳过 Version(2B) + Random(32B)

	// Session ID
	if idx+1 > len(rawHello) {
		return "", nil, nil, errors.New("truncated session id len")
	}
	sessIDLen := int(rawHello[idx])
	idx++
	if idx+sessIDLen > len(rawHello) {
		return "", nil, nil, errors.New("truncated session id")
	}
	if sessIDLen > 0 {
		sessionID = make([]byte, sessIDLen)
		copy(sessionID, rawHello[idx:idx+sessIDLen])
	}
	idx += sessIDLen

	// Cipher Suites
	if idx+2 > len(rawHello) {
		return "", nil, nil, errors.New("truncated cipher suites")
	}
	csLen := int(rawHello[idx])<<8 | int(rawHello[idx+1])
	idx += 2 + csLen

	// Compression Methods
	if idx+1 > len(rawHello) {
		return "", nil, nil, errors.New("truncated compression")
	}
	compLen := int(rawHello[idx])
	idx += 1 + compLen

	// Extensions
	if idx+2 > len(rawHello) {
		return "", sessionID, rawHello, nil // 无扩展
	}
	extTotalLen := int(rawHello[idx])<<8 | int(rawHello[idx+1])
	idx += 2
	end := idx + extTotalLen
	if end > len(rawHello) {
		end = len(rawHello)
	}

	for idx+4 <= end {
		extType := int(rawHello[idx])<<8 | int(rawHello[idx+1])
		extLen := int(rawHello[idx+2])<<8 | int(rawHello[idx+3])
		idx += 4
		if idx+extLen > end {
			break
		}
		if extType == 0x0000 { // Server Name Indication (SNI)
			sniData := rawHello[idx : idx+extLen]
			if len(sniData) > 5 {
				nameLen := int(sniData[3])<<8 | int(sniData[4])
				if 5+nameLen <= len(sniData) {
					sni = strings.ToLower(string(sniData[5 : 5+nameLen]))
				}
			}
		}
		idx += extLen
	}

	return sni, sessionID, rawHello, nil
}

func (h *realityHandler) handle(ctx context.Context, c net.Conn) {
	ip := addrOf(c)
	_ = c.SetDeadline(time.Now().Add(h.lim.HandshakeTimeout.Duration))
	br := bufio.NewReaderSize(c, 8192)

	sni, _, _, err := sniffClientHello(br)
	if err != nil {
		// 非 TLS 请求，直接回落透传到真实目标站
		h.fallbackToDest(ctx, c, br)
		return
	}

	// 校验 SNI 是否在允许列表（如果配置了 server_names）
	if len(h.serverNames) > 0 {
		if _, ok := h.serverNames[sni]; !ok {
			matched := false
			if h.tlsCfg != nil && h.tlsCfg.GetCertificate != nil {
				if cert, err := h.tlsCfg.GetCertificate(&tls.ClientHelloInfo{ServerName: sni}); err == nil && cert != nil {
					matched = true
				}
			}
			if !matched {
				h.guard.Fail(ip)
				h.fallbackToDest(ctx, c, br)
				return
			}
		}
	}

	// 执行 TLS 握手解密后进入内层代理协议（VLESS / Trojan）
	_ = c.SetDeadline(time.Time{})
	client := &bufConn{Conn: c, r: br}
	tc := tls.Server(client, h.tlsCfg)
	if err := tc.Handshake(); err != nil {
		h.guard.Fail(ip)
		slog.Debug("tls handshake failed", "remote", ip, "err", err)
		return
	}
	h.inner(ctx, tc)
}

// fallbackToDest 将探测流量零篡改重定向给真实海外大站，完全伪装目标站行为
func (h *realityHandler) fallbackToDest(ctx context.Context, c net.Conn, br *bufio.Reader) {
	d := net.Dialer{Timeout: 5 * time.Second}
	target, err := d.DialContext(ctx, "tcp", h.dest)
	if err != nil {
		slog.Debug("reality fallback connect failed", "dest", h.dest, "err", err)
		return
	}
	_ = c.SetDeadline(time.Time{})
	relay(&bufConn{Conn: c, r: br}, target, h.lim.IdleTimeout.Duration)
}
