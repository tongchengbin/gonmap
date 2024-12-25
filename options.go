package gonmap

type Options struct {
	ServiceProbes    string
	VersionIntensity int
	VersionTrace     bool
	DebugResponse    bool
	DebugRequest     bool
	Proxy            string
	ScanTimeout      int // 单个扫描目标的超时时间
	Timeout          int // 连接超时时间
}
