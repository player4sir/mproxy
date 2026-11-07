package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
)

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

var (
	errBadAddr       = errors.New("bad address format")
	errBufferTooSmall = errors.New("buffer too small")
)

// readAddr 从流中解析 SOCKS5 / Trojan / VLESS 格式的目标地址：ATYP + ADDR + PORT
func readAddr(r io.Reader) (host string, port int, err error) {
	var t [1]byte
	if _, err = io.ReadFull(r, t[:]); err != nil {
		return
	}
	switch t[0] {
	case 1: // IPv4: 4 bytes
		var ip [4]byte
		if _, err = io.ReadFull(r, ip[:]); err != nil {
			return
		}
		host = netip.AddrFrom4(ip).String()
	case 4: // IPv6: 16 bytes
		var ip [16]byte
		if _, err = io.ReadFull(r, ip[:]); err != nil {
			return
		}
		host = netip.AddrFrom16(ip).String()
	case 3: // Domain: 1 byte len + name
		var l [1]byte
		if _, err = io.ReadFull(r, l[:]); err != nil {
			return
		}
		if l[0] == 0 {
			return "", 0, errBadAddr
		}
		name := make([]byte, l[0])
		if _, err = io.ReadFull(r, name); err != nil {
			return
		}
		host = string(name)
	default:
		return "", 0, errBadAddr
	}
	var p [2]byte
	if _, err = io.ReadFull(r, p[:]); err != nil {
		return
	}
	port = int(binary.BigEndian.Uint16(p[:]))
	if port <= 0 || port > 65535 {
		return "", 0, errBadAddr
	}
	return
}

// writeAddr 将 host:port 序列化为 SOCKS5 / Trojan 格式的地址字节流
func writeAddr(buf []byte, host string, port int) ([]byte, error) {
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port %d", port)
	}
	var res []byte
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			res = append(buf, 0x01)
			b := ip.As4()
			res = append(res, b[:]...)
		} else {
			res = append(buf, 0x04)
			b := ip.As16()
			res = append(res, b[:]...)
		}
	} else {
		if len(host) > 255 {
			return nil, errors.New("domain name too long")
		}
		res = append(buf, 0x03, byte(len(host)))
		res = append(res, host...)
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], uint16(port))
	res = append(res, p[:]...)
	return res, nil
}

// parseAddrBytes 从 byte slice 解析地址与偏移量
func parseAddrBytes(b []byte) (host string, port int, offset int, err error) {
	if len(b) < 1 {
		return "", 0, 0, errBadAddr
	}
	atyp := b[0]
	idx := 1
	switch atyp {
	case 1:
		if len(b) < idx+4+2 {
			return "", 0, 0, errBadAddr
		}
		host = net.IP(b[idx : idx+4]).String()
		idx += 4
	case 4:
		if len(b) < idx+16+2 {
			return "", 0, 0, errBadAddr
		}
		host = net.IP(b[idx : idx+16]).String()
		idx += 16
	case 3:
		if len(b) < idx+1 {
			return "", 0, 0, errBadAddr
		}
		dlen := int(b[idx])
		idx++
		if len(b) < idx+dlen+2 {
			return "", 0, 0, errBadAddr
		}
		host = string(b[idx : idx+dlen])
		idx += dlen
	default:
		return "", 0, 0, errBadAddr
	}
	port = int(binary.BigEndian.Uint16(b[idx : idx+2]))
	idx += 2
	return host, port, idx, nil
}

func hostPort(h string, p int) string {
	return net.JoinHostPort(h, strconv.Itoa(p))
}

func ioReadFull(r io.Reader, b []byte) (int, error) {
	return io.ReadFull(r, b)
}

func containsFold(s, substr string) bool {
	if len(substr) > len(s) {
		return false
	}
	return bytes.Contains(bytes.ToLower([]byte(s)), bytes.ToLower([]byte(substr)))
}

// buildProxyProtocolV1Header 构造 PROXY protocol v1 头部（ASCII 字符串），
// 将真实客户端 IP/Port 透传给后端 Nginx/Caddy，防止日志全为 127.0.0.1
func buildProxyProtocolV1Header(src, dst net.Addr) []byte {
	sTCP, sOK := src.(*net.TCPAddr)
	dTCP, dOK := dst.(*net.TCPAddr)
	if !sOK || !dOK {
		return []byte("PROXY UNKNOWN\r\n")
	}
	proto := "TCP4"
	if sTCP.IP.To4() == nil {
		proto = "TCP6"
	}
	header := fmt.Sprintf("PROXY %s %s %s %d %d\r\n", proto, sTCP.IP.String(), dTCP.IP.String(), sTCP.Port, dTCP.Port)
	return []byte(header)
}

// randomPadding 生成抗 DPI 长度分析的随机填充字节
func randomPadding(min, max int) []byte {
	if max <= min || min < 0 {
		return nil
	}
	var b [2]byte
	_, _ = rand.Read(b[:])
	n := min + int(binary.BigEndian.Uint16(b[:]))%(max-min+1)
	pad := make([]byte, n)
	_, _ = rand.Read(pad)
	return pad
}
