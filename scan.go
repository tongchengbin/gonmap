package gonmap

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/logrusorgru/aurora"
	"io"
	"net"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	"golang.org/x/net/proxy"
)

type PortStatus int

const (
	StatusPortOpen  PortStatus = iota
	StatusPortClose PortStatus = iota
	StatusTlsError
	StatusWriteTimeout
	StatusReadTimeout
)

func (c PortStatus) String() string {
	switch c {
	case StatusPortOpen:
		return "Open"
	case StatusPortClose:
		return "Close"
	case StatusTlsError:
		return "TLS Error"
	case StatusWriteTimeout:
		return "Write Timeout"
	case StatusReadTimeout:
		return "Read Timeout"
	}
	return "Unknown"
}

type PortStatusCheck struct {
	Close int
	Open  int
}

func (p *PortStatusCheck) SetOpen() {
	p.Open++
}
func (p *PortStatusCheck) SetClose() {
	p.Close++
}
func (p *PortStatusCheck) IsClose() bool {
	if p.Open == 0 && p.Close >= 2 {
		return true
	}
	return false
}

type SocketStatus struct {
	status PortStatus
	data   []byte
	err    error
}

func (n *Nmap) ScanAddress(protocol Protocol, address string) (response *Response, err error) {
	ip, port, err := ParseAddress(address)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	response = n.ScanTimeout(ctx, protocol, ip, port,
		time.Duration(n.option.Timeout)*time.Second,
		time.Duration(n.option.Timeout)*time.Second*10)
	return response, nil
}

func (n *Nmap) ScanTimeout(ctx context.Context, protocol Protocol, ip string, port int, timeout, maxTimeout time.Duration) (response *Response) {
	// 两种取消方式一种 ctx 取消 一种是 最大超时时间取消 这里只限制最大超时时间 即一个目标检测的最大超时时间
	ctx, cancel := context.WithTimeout(ctx, maxTimeout)
	defer cancel()
	if port == 53 {
		protocol = UDP
	}
	response = &Response{Status: StatusUnknown, Address: fmt.Sprintf("%s:%d", ip, port), Protocol: protocol}
	go func() {
		defer cancel()
		switch protocol {
		case TCP:
			response = n.ScanTCP(ctx, ip, port, timeout)
		case UDP:
			response = n.ScanUdp(ctx, ip, port, timeout)
		default:
			panic(protocol)
		}
	}()
	select {
	case <-ctx.Done():
		return response
	}
}

func (n *Nmap) ScanProbes(protocol Protocol, address string, timeout time.Duration) (response *Response, err error) {
	ip, port, err := ParseAddress(address)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	response = n.ScanTimeout(ctx, protocol, ip, port, timeout, timeout)
	return response, nil
}

func (n *Nmap) ScanTCP(ctx context.Context, ip string, port int, timeout time.Duration) (response *Response) {
	if timeout < time.Duration(1)*time.Second {
		gologger.Warning().Msgf("timeout too small: %vs", timeout.Seconds())
		timeout = time.Duration(10) * time.Second
	}
	response = &Response{Status: StatusUnknown, Address: fmt.Sprintf("%s:%d", ip, port), Protocol: TCP}
	// create dialer
	dialer, err := NewDialer(n.option.Proxy, timeout)
	if err != nil {
		gologger.Error().Msgf("Failed to create dialer: %s", err)
		return response
	}
	address := fmt.Sprintf("%s:%d", ip, port)
	isTls := false
	probesSorts := sortProbes(n.tcpProbes, port, false)
	if 0 == len(probesSorts) {
		return response
	}
	i := 0
	statusCheck := PortStatusCheck{}

	for {
		select {
		case <-ctx.Done():
			return response
		default:
		}
		if i >= len(probesSorts) {
			break
		}
		pb := probesSorts[i]
		// 放在这里++ 是避免后面continue 忘记++
		i++
		if n.option.VersionTrace {
			if isTls {
				gologger.Print().Msgf("Service scan sending probe %s to tls:%s (tcp)", pb.Name, address)
			} else {
				gologger.Print().Msgf("Service scan sending probe %s to %s (tcp) ", pb.Name, address)
			}
		}
		t1 := time.Now()
		banner, code := n.tcpSend(dialer, address, isTls, pb, timeout)
		if n.option.DebugResponse {
			gologger.Print().Msgf("Read request from [%s] [%s] (timeout: %s)\n%s", address, aurora.Cyan(code.String()), time.Now().Sub(t1).String(), FormatBytesToHex(banner))
		}
		costTime := time.Now().Sub(t1)
		// check
		if len(banner) == 0 && pb.isTcpWrapPossible() && costTime < pb.tcpwrappedms && statusCheck.Open == 0 {
			response.Status = StatusTcpWrapped
			return response
		}
		if code == StatusPortClose {
			statusCheck.SetClose()
			if statusCheck.IsClose() {
				response.Status = StatusClose
				return response
			}
			continue
		} else if code == StatusTlsError {
			continue
		} else if code == StatusWriteTimeout {
			continue
		} else if code == StatusReadTimeout && len(banner) == 0 {
			statusCheck.SetOpen()
			continue
		}
		statusCheck.SetOpen()
		finger := pb.match(banner)
		if finger != nil {
			gologger.Debug().Msgf("Matched :%v with %s:%d %v", finger.Service, pb.Name, finger.match.line, finger.Version)
			if pb.Name == "TLSSessionReq" || pb.Name == "SSLSessionReq" {
				isTls = true
				probesSorts = sortProbes(n.tcpProbes, port, true)
				i = 0
				continue
			}
			finger.Response = banner
			finger.Service = fixServiceName(finger.Service, isTls)
			response.Status = StatusMatched
			response.Tls = isTls
			response.Service = finger
			return response
		}
	}
	response.Status = StatusUnknown
	return response
}

func (n *Nmap) ScanUdp(ctx context.Context, ip string, port int, timeout time.Duration) (response *Response) {
	// 根据端口获取默认协议
	address := fmt.Sprintf("%s:%d", ip, port)
	remoteAddr, _ := net.ResolveUDPAddr("udp", address)
	response = &Response{Status: StatusUnknown, Address: fmt.Sprintf("%s:%d", ip, port), Protocol: UDP}
	for _, pb := range n.udpProbes {
		select {
		case <-ctx.Done():
			return response
		default:
		}
		sendRaw := strings.Replace(pb.sendRaw, "{Host}", fmt.Sprintf("%s:%d", ip, port), -1)
		banner, err := udpSend(remoteAddr, []byte(sendRaw), timeout)
		if err != nil && strings.Contains(err.Error(), "STEP1:CONNECT") {
			response.Status = StatusClose
			return response
		}
		if n.option.DebugResponse {
			gologger.Info().Msgf("banner:%v", string(banner))
		}
		if finger := n.Match(UDP, banner, pb.Name); finger != nil {
			response.Status = StatusMatched
			response.Service = finger
			return response
		}
	}
	response.Status = StatusUnknown
	return response
}

func (n *Nmap) tcpSend(dialer proxy.Dialer, address string, ssl bool, pb *probe, duration time.Duration) ([]byte, PortStatus) {
	var maxWait time.Duration
	if pb.totalWaiTms > 0 {
		maxWait = pb.totalWaiTms
	} else {
		maxWait = time.Second * 30
	}
	if duration > maxWait {
		duration = maxWait
	}
	ctx, cancel := context.WithTimeout(context.Background(), maxWait)
	defer cancel()
	if n.option.VersionTrace {
		gologger.Debug().Msgf("Service scan sending probe %s to %s (tcp)", pb.Name, address)
	}
	data := strings.Replace(pb.sendRaw, "{Host}", address, -1)
	if n.option.DebugRequest {
		gologger.Print().Msgf("Send Prob:%s raw\n%s", pb.Name, FormatBytesToHex([]byte(data)))
	}
	//读取数据
	socketStatus := &SocketStatus{}
	done := make(chan bool)
	// 这里主要控制指纹中的WaitMS
	go func() {
		sendProbe(ctx, dialer, address, ssl, []byte(data), duration, socketStatus)
		done <- true
		close(done)
	}()

	select {
	case <-done:
		return socketStatus.data, socketStatus.status
	case <-ctx.Done():
		return socketStatus.data, socketStatus.status
	}
}

func sendProbe(ctx context.Context, dialer proxy.Dialer, address string, ssl bool, data []byte, timeout time.Duration, conStatus *SocketStatus) {
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		gologger.Debug().Msgf("CreteCon Error:%v", err)
		conStatus.status = StatusPortClose
		return
	}
	defer conn.Close()
	if ssl {
		tlsConn := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true,
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			gologger.Debug().Msgf("TLS Error:%v", err)
			conStatus.status = StatusTlsError
			return
		}
		conn = tlsConn
	}
	if len(data) > 0 {
		_, err = conn.Write(data)
		if err != nil {
			gologger.Debug().Msgf("Write Error:%v", err)
			conStatus.status = StatusWriteTimeout
			return
		}
	}
	size := 4096
	var tmp = make([]byte, 1024)
	var length int
	for {
		select {
		case <-ctx.Done():
			// 如果已经读取到数据，保持 StatusPortOpen
			if len(conStatus.data) > 0 {
				conStatus.status = StatusPortOpen
			} else {
				conStatus.status = StatusReadTimeout
			}
			return
		default:
			if len(conStatus.data) > size {
				return
			}
			err = conn.SetReadDeadline(time.Now().Add(timeout))
			length, err = conn.Read(tmp)
			if err != nil {
				gologger.Debug().Msgf("Read Error:%v", err)
			}
			if length > 0 {
				conStatus.status = StatusPortOpen
				// 填充数据
				conStatus.data = append(conStatus.data, tmp[:length]...)
				if length < len(tmp) {
					return
				}
				continue
			}
			if err == nil {
				if length > 0 && length < len(tmp) {
					return
				}
			} else if errors.Is(err, io.EOF) {
				return
			} else {
				gologger.Debug().Msgf("Read Error:%v", err)
				if len(conStatus.data) == 0 {
					conStatus.status = StatusReadTimeout
				}
				return
			}
		}
	}
}

func udpSend(remoteAddr *net.UDPAddr, data []byte, timeout time.Duration) ([]byte, error) {
	conn, err := net.DialUDP("udp", nil, remoteAddr)
	if err != nil {
		return nil, errors.New(err.Error() + " STEP1:CONNECT")
	}
	_, err = conn.Write(data)
	if err != nil {
		return nil, err
	}
	var buf []byte
	var tmp = make([]byte, 256)
	for {
		err = conn.SetReadDeadline(time.Now().Add(timeout))
		if err != nil {
			return nil, err
		}
		n, _, err := conn.ReadFromUDP(tmp)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				return nil, errors.New(err.Error() + " STEP3:READ")
			}
		}
		buf = append(buf, tmp[:n]...)
		if n < len(tmp) {
			break
		}
	}
	return buf, nil
}

func fixServiceName(serviceName string, ssl bool) string {
	if ssl && serviceName == "http" {
		return "https"
	}
	return serviceName

}
