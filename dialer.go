package gonmap

import (
	"net"
	"net/url"
	"time"

	"golang.org/x/net/proxy"
)

func NewDialer(proxyAddr string, timeout time.Duration) (proxy.Dialer, error) {
	var dialer proxy.Dialer
	var err error
	var proxyURL *url.URL
	if proxyAddr != "" {
		// 使用 SOCKS5 代理
		proxyURL, err = url.Parse(proxyAddr)
		if err != nil {
			return nil, err
		}
		dialer, err = proxy.FromURL(proxyURL, &net.Dialer{
			Timeout: timeout,
		})
		if err != nil {
			return nil, err
		}
	} else {
		// 直接连接
		dialer = &net.Dialer{
			Timeout: timeout,
		}
	}
	return dialer, nil
}
