package main

import (
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/tongchengbin/gonmap/internal"
	_ "net/http/pprof"
)

const Version = "v0.3.0"

var Banner = fmt.Sprintf(`
version: %s
author:  https://github.com/tongchengbin/gonmap
$$$$$$\   $$$$$$\  $$\   $$\ $$\      $$\  $$$$$$\  $$$$$$$\  
$$  __$$\ $$  __$$\ $$$\  $$ |$$$\    $$$ |$$  __$$\ $$  __$$\ 
$$ /  \__|$$ /  $$ |$$$$\ $$ |$$$$\  $$$$ |$$ /  $$ |$$ |  $$ |
$$ |$$$$\ $$ |  $$ |$$ $$\$$ |$$\$$\$$ $$ |$$$$$$$$ |$$$$$$$  |
$$ |\_$$ |$$ |  $$ |$$ \$$$$ |$$ \$$$  $$ |$$  __$$ |$$  ____/ 
$$ |  $$ |$$ |  $$ |$$ |\$$$ |$$ |\$  /$$ |$$ |  $$ |$$ |      
\$$$$$$  | $$$$$$  |$$ | \$$ |$$ | \_/ $$ |$$ |  $$ |$$ |      
 \______/  \______/ \__|  \__|\__|     \__|\__|  \__|\__|
`, Version)

func main() {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelWarning)
	options := internal.ParseOptions()
	if options.Debug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	}
	if options.Version {
		gologger.Info().Msgf("AppFinger Version: %s", Version)
		return
	}
	if options.UpdateRule {
		return
	}
	runner, err := internal.NewRunner(options)
	if err != nil {
		gologger.Error().Msgf(err.Error())
		return
	}
	fmt.Printf(Banner)
	err = runner.Enumerate()
	if err != nil {
		gologger.Error().Msgf(err.Error())
		return
	}
}
