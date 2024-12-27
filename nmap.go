package gonmap

import (
	"os"

	"github.com/projectdiscovery/gologger"
	"golang.org/x/net/proxy"
)

type Nmap struct {
	probeNameMap map[string]*probe
	tcpProbes    []*probe
	udpProbes    []*probe
	rarity       int
	ShowBanner   bool
	dialer       proxy.Dialer
	option       *Options
}

func New(option *Options) *Nmap {
	nmap := &Nmap{
		probeNameMap: make(map[string]*probe),
		option:       option,
	}
	err := nmap.init()
	if err != nil {
		panic(err)
	}
	return nmap
}

func (n *Nmap) init() error {
	var probeList []*probe
	if n.option.ServiceProbes == "" {
		probeList = LoadProbes(probes, n.option.VersionIntensity)
	} else {
		probesData, err := os.ReadFile(n.option.ServiceProbes)
		if err != nil {
			return err
		}
		probeList = LoadProbes(string(probesData), n.option.VersionIntensity)
	}
	for _, p := range probeList {
		if p.protocol == TCP {
			n.tcpProbes = append(n.tcpProbes, p)
		} else {
			n.udpProbes = append(n.udpProbes, p)
		}
	}
	n.setFallback(n.tcpProbes)
	gologger.Debug().Msgf("Loaded %d tcp probes and %d udp probes", len(n.tcpProbes), len(n.udpProbes))
	return nil
}

func (n *Nmap) GetUdpProbe() []*probe {
	return n.udpProbes
}
func (n *Nmap) GetTcpProbe() []*probe {
	return n.tcpProbes
}

func (n *Nmap) setFallback(ps []*probe) {
	probeMap := make(map[string]*probe)
	for _, p := range ps {
		probeMap[p.Name] = p
	}
	for _, pb := range ps {
		for _, fb := range pb.fallback {
			if _, ok := probeMap[fb]; ok {
				pb.fallbackProbe = append(pb.fallbackProbe, probeMap[fb])
			}

		}
	}
}

//func (n *Nmap) ScanTCP(ctx context.Context, ip string, port int) (response *Response) {
//	timeout := time.Duration(n.option.Timeout) * time.Second
//	maxTimeout := time.Duration(n.option.ScanTimeout) * time.Second
//	ctx = context.Background()
//	response = n.ScanWithCtx(ctx, "tcp", ip, port, timeout, maxTimeout)
//	return response
//}

func (n *Nmap) Match(protocol Protocol, banner []byte, firstProbe string) *MatchResult {
	// Service scan match (Probe HTTPOptions matched with NULL line 3571): 103.133.154.250:2222 is ssh.  Version: |OpenSSH|9.2p1|protocol 2.0|
	//	Nmap 匹配指纹不一定是对应的探针
	var ms []*probe
	if protocol == TCP {
		ms = n.tcpProbes
	} else {
		ms = n.udpProbes
	}
	for _, p := range ms {
		if p.Name == firstProbe {
			if f := p.match(banner); f != nil {
				return f
			}
		}
	}
	for _, p := range ms {
		if p.Name != firstProbe {
			if f := p.match(banner); f != nil {
				return f
			}
		}
	}
	return nil
}
