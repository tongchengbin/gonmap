package gonmap

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

func FormatBytesToHex(data []byte) string {
	var builder strings.Builder
	for _, b := range data {
		if b == '\r' || b == '\n' {
			builder.WriteByte(b)
		} else if 32 <= b && b < 127 {
			builder.WriteByte(b)
		} else {
			builder.WriteString(fmt.Sprintf("\\x%02x", b))
		}
	}
	return builder.String()
}

func ParseTarget(target string) (string, int) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		host = target
		portStr = "80"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		port = 80
	}
	return host, port
}

func ParseAddress(address string) (string, int, error) {
	ip, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, err
	}
	return ip, port, nil
}
