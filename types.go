package gonmap

type MatchResult struct {
	Service  string
	Version  string
	Product  string
	Response []byte
	match    *match
}

type Status string

const (
	StatusClose      Status = "close"
	StatusUnknown    Status = "unknown"
	StatusMatched    Status = "matched"
	StatusTcpWrapped Status = "tcpwrapped"
)

type Response struct {
	Address  string       `json:"address"`
	Tls      bool         `json:"tls"`
	Status   Status       `json:"status"`
	Service  *MatchResult `json:"service"`
	Protocol Protocol     `json:"protocol"`
}
