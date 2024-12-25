package gonmap

import (
	"errors"
	"github.com/dlclark/regexp2"
	"regexp"
	"strings"
)

type versionMate struct {
	ProbeName        string
	MatchRegexString string
	Service          string
	ProductName      string
	Version          string
	Info             string
	Hostname         string
	OperatingSystem  string
	DeviceType       string
	match            *match
}

// match 匹配规则
type match struct {
	soft        bool
	service     string
	pattern     string
	regex       *regexp2.Regexp
	versionMate *versionMate
	line        int
}

var matchVersionInfoRegexps = map[string]*regexp.Regexp{
	"PRODUCTNAME": regexp.MustCompile("p/([^/]+)/"),
	"VERSION":     regexp.MustCompile("v/([^/]+)/"),
	"INFO":        regexp.MustCompile("i/([^/]+)/"),
	"HOSTNAME":    regexp.MustCompile("h/([^/]+)/"),
	"OS":          regexp.MustCompile("o/([^/]+)/"),
	"DEVICE":      regexp.MustCompile("d/([^/]+)/"),
}

func FixProtocol(oldProtocol string) string {
	//进行最后输出修饰
	if oldProtocol == "ssl/http" {
		return "https"
	}
	if oldProtocol == "http-proxy" {
		return "http"
	}
	if oldProtocol == "microsoft-ds" {
		return "smb"
	}
	if oldProtocol == "netbios-ssn" {
		return "netbios"
	}
	if oldProtocol == "oracle-tns" {
		return "oracle"
	}
	if oldProtocol == "msrpc" {
		return "rpc"
	}
	if oldProtocol == "ms-sql-s" {
		return "mssql"
	}
	if oldProtocol == "domain" {
		return "dns"
	}
	if oldProtocol == "svnserve" {
		return "svn"
	}
	if oldProtocol == "ibm-db2" {
		return "db2"
	}
	if oldProtocol == "socks-proxy" {
		return "socks5"
	}
	if len(oldProtocol) > 4 {
		if oldProtocol[:4] == "ssl/" {
			return oldProtocol[4:] + "-ssl"
		}
	}
	oldProtocol = strings.ReplaceAll(oldProtocol, "_", "-")
	return oldProtocol
}

func extractCPEValue(part string) string {
	start := len("cpe:/a:")
	end := strings.Index(part[start:], "/") + start
	if end > start {
		return part[start:end]
	}
	return part[start:]
}
func extractValues(s string) map[string]string {
	values := make(map[string]string)
	parts := strings.Split(s, " ")

	for _, part := range parts {
		if strings.HasPrefix(part, "p/") {
			values["p"] = extractValue(part, "p/")
		} else if strings.HasPrefix(part, "v/") {
			values["v"] = extractValue(part, "v/")
		} else if strings.HasPrefix(part, "i/") {
			values["i"] = extractValue(part, "i/")
		} else if strings.HasPrefix(part, "cpe:/a:") {
			values["cpe"] = extractCPEValue(part)
		}
	}

	return values
}

func extractValue(part, prefix string) string {
	start := len(prefix)
	end := strings.Index(part[start:], "/") + start
	if end > start {
		return part[start:end]
	}
	return part[start:]
}

func parseMatch(s string, soft bool) *match {
	var m = &match{}
	// 查找第一个空格前的字符串
	index := strings.Index(s, " ")
	m.service = s[:index]
	s = strings.Trim(s[index+1:], " ")
	// 查找匹配的正则
	if s[:1] != "m" {
		panic(errors.New("match 语句参数不正确: " + s[:1]))
		return nil
	}
	var mf = s[1:2]
	var mStart = 2
	// 找到结束符
	var end = strings.Index(s[mStart:], mf)
	var pattern = s[mStart : mStart+end]
	// 判断是否有选项
	var patternOpt string
	if len(s) > (mStart+end+2) && s[mStart+end+1:mStart+end+2] != " " {
		patternOpt = s[mStart+end+1 : mStart+end+2]
	} else {
		patternOpt = ""
	}
	s = s[mStart+end+len(patternOpt):]

	m.soft = soft
	m.service = FixProtocol(m.service)
	m.pattern = pattern
	m.regex = getPatternRegexp(pattern, patternOpt)
	meta := extractValues(s)
	m.versionMate = &versionMate{}
	for k, v := range meta {
		switch k {
		case "p":
			m.versionMate.ProductName = v
		case "v":
			m.versionMate.Version = v
		case "i":
			m.versionMate.Info = v
		case "cpe":
			m.versionMate.ProbeName = v
		}
	}
	return m
}
func getPatternRegexp(pattern string, opt string) *regexp2.Regexp {
	pattern = strings.ReplaceAll(pattern, `\0`, `\x00`)
	var o regexp2.RegexOptions
	switch opt {
	case "i":
		o = regexp2.IgnoreCase
	case "s":
		o = regexp2.Singleline
	default:
		o = regexp2.None
	}
	return regexp2.MustCompile(pattern, o)
}
func (m *match) getVersionInfo(s string, regID string) string {
	if matchVersionInfoRegexps[regID].MatchString(s) {
		return matchVersionInfoRegexps[regID].FindStringSubmatch(s)[1]
	} else {
		return ""
	}
}
