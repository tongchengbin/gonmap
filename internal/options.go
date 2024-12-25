package internal

import (
	"fmt"
	"github.com/projectdiscovery/goflags"
	"io"
	"os"
)

type RunnerOptions struct {
	TargetFile        string
	Address           goflags.StringSlice
	Threads           int
	Timeout           int
	Proxy             string
	Output            io.Writer
	OutputFile        string
	OutputType        string
	Stdin             bool
	ServiceProbes     string
	Debug             bool
	UpdateRule        bool
	DisableIcon       bool
	DisableJavaScript bool
	Version           bool
	DebugResp         bool
	VersionIntensity  int
	VersionTrace      bool
	DebugReq          bool
	ScanTimeout       int
}

func ParseOptions() *RunnerOptions {
	options := &RunnerOptions{}
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`AppFinger is a web application fingerprint scanner.`)
	flagSet.CreateGroup("AppFinger", "AppFinger",
		flagSet.StringVarP(&options.TargetFile, "url-file", "l", "", "File containing urls to scan"),
		flagSet.StringSliceVarP(&options.Address, "url", "t", nil, "target url to scan (-u INPUT1 -u INPUT2)", goflags.CommaSeparatedStringSliceOptions),
		flagSet.IntVar(&options.Threads, "threads", 32, "Number of concurrent threads (default 10)"),
		flagSet.IntVar(&options.Timeout, "timeout", 10, "Timeout in seconds (default 10)"),
		flagSet.StringVarP(&options.Proxy, "proxy", "x", "", "HTTP proxy to use for requests (e.g. http://127.0.0.1:7890)"),
		flagSet.BoolVarP(&options.Stdin, "stdin", "s", false, "Read urls from stdin"),
		flagSet.StringVarP(&options.ServiceProbes, "finger-home", "sp", "", "finger yaml directory home default is built-in"),
		flagSet.BoolVarP(&options.UpdateRule, "update-rule", "ur", false, "update rule from github.com/tongchengbin/appfinger"),
		flagSet.BoolVarP(&options.DisableIcon, "disable-icon", "di", false, "disabled icon request to matcher"),
		flagSet.BoolVarP(&options.DisableJavaScript, "disable-js", "dj", false, "disabled matcher javascript rule"),
		flagSet.BoolVar(&options.DebugResp, "debug-resp", false, "debug response"),
		flagSet.BoolVarP(&options.Version, "version", "v", false, "show version"),
	)
	flagSet.CreateGroup("Help", "Help",
		flagSet.BoolVar(&options.Debug, "debug", false, "debug"),
	)
	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&options.OutputFile, "output", "o", "", "file to write output to"),
		flagSet.StringVar(&options.OutputType, "output-format", "txt", "输出文件格式"),
	)
	if err := flagSet.Parse(); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	return options
}
