package internal

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/tongchengbin/gonmap"
	"io"
	"os"
	"strings"
	"sync"
)

type Runner struct {
	options  *RunnerOptions
	client   *gonmap.Nmap
	callback func(response *gonmap.Response)
	outputs  []io.Writer
}

func NewRunner(options *RunnerOptions) (*Runner, error) {
	// check if finger home is set
	client := gonmap.New(&gonmap.Options{
		ServiceProbes:    options.ServiceProbes,
		VersionIntensity: options.VersionIntensity,
		VersionTrace:     options.VersionTrace,
		DebugResponse:    options.DebugResp,
		DebugRequest:     options.DebugReq,
		Proxy:            options.Proxy,
		ScanTimeout:      options.ScanTimeout,
		Timeout:          options.Timeout,
	})
	runner := &Runner{
		options: options,
		client:  client,
	}
	var outputs []io.Writer
	if options.OutputFile != "" {
		outputWriter := NewOutputWriter(true)
		file, err := outputWriter.createFile(options.OutputFile, true)
		if err != nil {
			gologger.Error().Msgf("Could not create file for %s: %s\n", options.OutputFile, err)
			return nil, err
		}
		outputs = append(outputs, file)

	}
	runner.outputs = outputs
	runner.callback = func(response *gonmap.Response) {
		for _, output := range outputs {
			s, _ := json.Marshal(response)
			_, _ = output.Write(append(s, "\n"...))
		}
		if response.Status == gonmap.StatusMatched {
			l := fmt.Sprintf("[%s] %s", aurora.Green(response.Address).String(), response.Service.Service)
			if response.Service.Version != "" {
				l += fmt.Sprintf(" (%s)", response.Service.Version)
			}
			gologger.Info().Msgf(l)
		}

	}
	return runner, nil

}

func (r *Runner) EnumerateMultiple(ctx context.Context, reader io.Reader) error {
	scanner := bufio.NewScanner(reader)
	targets := make(chan string, 10)
	var wg sync.WaitGroup
	for i := 0; i < r.options.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for address := range targets {
				response, err := r.client.ScanAddress(gonmap.TCP, address)
				if err != nil {
					gologger.Warning().Msgf("Failed to scan %s: %s\n", address, err)
				}
				r.callback(response)
			}
		}()
	}
	for scanner.Scan() {
		target, err := sanitize(scanner.Text())
		if err != nil {
			continue
		}
		targets <- target
	}
	close(targets)
	wg.Wait()
	return nil
}

func (r *Runner) Enumerate() error {
	ctx := context.Background()
	if r.options.OutputFile != "" {
		outputWriter := NewOutputWriter(true)
		file, err := outputWriter.createFile(r.options.OutputFile, true)
		if err != nil {
			gologger.Error().Msgf("Could not create file for %s: %s\n", r.options.OutputFile, err)
			return err
		}
		err = file.Close()
		if err != nil {
			return err
		}
	}
	// If we have multiple domains as input,
	if len(r.options.Address) > 0 {
		reader := strings.NewReader(strings.Join(r.options.Address, "\n"))
		return r.EnumerateMultiple(ctx, reader)
	}
	if r.options.TargetFile != "" {
		f, err := os.Open(r.options.TargetFile)
		if err != nil {
			return err
		}
		err = r.EnumerateMultiple(ctx, f)
		_ = f.Close()
		return err
	}
	if r.options.Stdin {
		return r.EnumerateMultiple(ctx, os.Stdin)
	}
	return nil
}

var (
	ErrEmptyInput = errors.New("empty data")
)

func sanitize(data string) (string, error) {
	data = strings.Trim(data, "\n\t\"' ")
	if data == "" {
		return "", ErrEmptyInput
	}
	return data, nil
}
