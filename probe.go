package gonmap

import (
	"bufio"
	_ "embed"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type Protocol string

const (
	TCP Protocol = "TCP"
	UDP Protocol = "UDP"
)

//go:embed nmap-service-probes
var probes string

var probeExprRegx = regexp.MustCompile("^(UDP|TCP) ([a-zA-Z0-9-_./]+) (?:q\\|([^|]*)\\|)")
var probeIntRegx = regexp.MustCompile(`^(\d+)$`)

// Helper function to convert a hexadecimal string to a byte
func hexToByte(hex string) (byte, error) {
	b, err := strconv.ParseInt(hex, 16, 0)
	if err != nil {
		return 0, err
	}
	return byte(b), nil
}

func buildString(str string) string {
	// 转移\\0  为\0
	str = strings.ReplaceAll(str, `\0`, string(byte(0)))
	re := regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
	result := re.ReplaceAllStringFunc(str, func(match string) string {
		// Extract the hexadecimal value from the matched \x sequence
		hexValue := match[2:]
		// Parse the hexadecimal value and convert it to a byte
		b, err := hexToByte(hexValue)
		if err == nil {
			return string([]byte{b})
		} else {
			return match
		}
	})
	result = strings.ReplaceAll(result, "\\r", "\r")
	result = strings.ReplaceAll(result, "\\n", "\n")
	return result
}

func isCommand(line string) bool {
	// 判断是否为探针指令
	if len(line) < 2 {
		return false
	}
	if line[:1] == "#" {
		return false
	}
	commandName := line[:strings.Index(line, " ")]
	commandArr := []string{
		"Exclude", "Probe", "match", "softmatch", "ports", "sslports", "totalwaitms", "tcpwrappedms", "rarity", "fallback",
	}
	for _, item := range commandArr {
		if item == commandName {
			return true
		}
	}
	return false
}

type probe struct {
	//探针级别
	rarity int
	//探针名称
	Name string
	//探针适用默认端口号
	ports PortList
	//探针适用SSL端口号
	sslports PortList

	totalWaiTms  time.Duration
	tcpwrappedms time.Duration

	//探针对应指纹库
	matchGroup []*match
	//探针指纹库若匹配失败，则会尝试使用fallback指定探针的指纹库
	fallback      []string
	fallbackProbe []*probe
	//探针发送协议类型
	protocol Protocol
	//探针发送数据
	sendRaw string
	// 包含的所有服务 ，用于优先匹配
	services map[string]struct{}
}

func (p *probe) match(banner []byte) *MatchResult {
	for _, m := range p.matchGroup {
		matcher, err := m.regex.FindStringMatch(string(banner))
		if err != nil {
			continue
		}
		if matcher == nil {
			continue
		}
		if len(matcher.Groups()) == 0 {
			continue
		}
		var result = &MatchResult{Response: banner, Service: m.service, match: m}
		var groups = map[string]string{}
		if len(matcher.Groups()) > 1 {
			for index, group := range matcher.Groups() {
				groups[fmt.Sprintf("$%d", index)] = group.String()
			}
		}
		if m.versionMate.Version != "" {
			result.Version = groups[m.versionMate.Version]
		}
		if m.versionMate.ProductName != "" {
			result.Product = groups[m.versionMate.ProductName]
		}
		return result
	}
	return nil
}

func (p *probe) loadLine(s string, index int) {
	//分解命令
	index += 1
	i := strings.Index(s, " ")
	commandName := s[:i]
	commandArgs := s[i+1:]
	commandArgs = strings.TrimSpace(commandArgs)
	//逐行处理
	switch commandName {
	case "Probe":
		p.loadProbe(commandArgs)
	case "match":
		p.loadMatch(commandArgs, false, index)
	case "softmatch":
		p.loadMatch(commandArgs, true, index)
	case "ports":
		p.loadPorts(commandArgs, false)
	case "sslports":
		p.loadPorts(commandArgs, true)
	case "totalwaitms":
		p.totalWaiTms = time.Duration(p.getInt(commandArgs)) * time.Millisecond
	case "tcpwrappedms":
		p.tcpwrappedms = time.Duration(p.getInt(commandArgs)) * time.Millisecond
	case "rarity":
		p.rarity = p.getInt(commandArgs)
	case "fallback":
		p.fallback = p.getString(commandArgs)
	}
}

func (p *probe) loadProbe(s string) {
	if !probeExprRegx.MatchString(s) {
		panic(errors.New("probe 语句格式不正确:" + s))
	}
	args := probeExprRegx.FindStringSubmatch(s)
	if args[1] == "" || args[2] == "" {
		panic(errors.New("probe 参数格式不正确"))
	}
	if args[1] == string(TCP) {
		p.protocol = TCP
	} else if args[1] == string(UDP) {
		p.protocol = UDP
	} else {
		panic(errors.New(fmt.Sprintf("probe 参数格式不正确(%v)", args)))
	}
	p.Name = args[2]
	str := args[3]
	p.sendRaw = buildString(str)
}

func (p *probe) loadMatch(s string, soft bool, index int) {
	m := parseMatch(s, soft)
	m.line = index
	p.matchGroup = append(p.matchGroup, m)
	p.services[m.service] = struct{}{}
}

func (p *probe) loadPorts(expr string, ssl bool) {
	if ssl {
		p.sslports = parsePortList(expr)
	} else {
		p.ports = parsePortList(expr)
	}
}

func (p *probe) getInt(expr string) int {
	if !probeIntRegx.MatchString(expr) {
		panic(errors.New("totalwaitms or tcpwrappedms 语句参数不正确"))
	}
	i, _ := strconv.Atoi(probeIntRegx.FindStringSubmatch(expr)[1])
	return i
}

func (p *probe) getString(expr string) []string {
	var pbs []string
	fb := ""

	for _, pb := range expr {
		if unicode.IsDigit(pb) || unicode.IsLetter(pb) {
			fb += string(pb)
			continue
		}
		if pb == ',' {
			pbs = append(pbs, fb)
			fb = ""
			continue
		}
	}
	if fb != "" {
		pbs = append(pbs, fb)
	}
	return pbs
}

func (p *probe) isTcpWrapPossible() bool {
	return p.tcpwrappedms > 0
}

func (p *probe) isNullProbe() bool {
	return p.Name == "NULL"
}

var portRangeRegx = regexp.MustCompile("^(\\d+)(?:-(\\d+))?$")
var portGroupRegx = regexp.MustCompile("^(\\d+(?:-\\d+)?)(?:,\\d+(?:-\\d+)?)*$")

type PortList []int

func parsePortList(express string) PortList {
	var list = PortList([]int{})
	if portGroupRegx.MatchString(express) == false {
		panic("port expression string invalid")
	}
	for _, expr := range strings.Split(express, ",") {
		rArr := portRangeRegx.FindStringSubmatch(expr)
		var startPort, endPort int
		startPort, _ = strconv.Atoi(rArr[1])
		if rArr[2] != "" {
			endPort, _ = strconv.Atoi(rArr[2])
		} else {
			endPort = startPort
		}
		for num := startPort; num <= endPort; num++ {
			list = append(list, num)
		}
	}
	list = list.removeDuplicate()
	return list
}

func (p PortList) removeDuplicate() PortList {
	result := make([]int, 0, len(p))
	temp := map[int]struct{}{}
	for _, item := range p {
		if _, ok := temp[item]; !ok { //如果字典中找不到元素，ok=false，!ok为true，就往切片中append元素。
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

func (p PortList) exist(port int) bool {
	for _, num := range p {
		if num == port {
			return true
		}
	}
	return false
}

func LoadProbes(s string, versionIntensity int) []*probe {
	scanner := bufio.NewScanner(strings.NewReader(s))
	var pb = &probe{services: map[string]struct{}{}, matchGroup: make([]*match, 0)}
	var probeList = make([]*probe, 0)
	lineIndex := 0
	for scanner.Scan() {
		line := scanner.Text()
		if !isCommand(line) {
			continue
		}
		commandName := line[:strings.Index(line, " ")]
		if commandName == "Probe" {
			if len(pb.matchGroup) > 0 {
				if pb.rarity <= versionIntensity || versionIntensity == 9 {
					probeList = append(probeList, pb)
				}
				pb = &probe{services: map[string]struct{}{}, matchGroup: make([]*match, 0)}
			}
		}
		pb.loadLine(line, lineIndex)
		lineIndex++
	}
	if len(pb.matchGroup) > 0 {
		probeList = append(probeList, pb)
	}
	return probeList
}

func sortProbes(probes []*probe, port int, ssl bool) []*probe {
	// 根据端口信息返回检测序列包
	/*
		总共的探针不超过100 所以这里直接遍历 不需要考虑性能
	*/
	var probesSorts []*probe
	var others []*probe
	for _, pb := range probes {
		if (pb.ports.exist(port) && !ssl) || (pb.sslports.exist(port) && ssl) {
			probesSorts = append(probesSorts, pb)
			continue
		}
		others = append(others, pb)
	}
	probesSorts = append(probesSorts, others...)
	return probesSorts
}
func perfSort(port int, ps []*probe) []*probe {
	if pn, ok := PortRequest[port]; ok {
		for i, pb := range ps {
			if pb.Name == pn {
				return append([]*probe{pb}, append(ps[:i], ps[i+1:]...)...)
			}
		}
	}
	return ps
}
