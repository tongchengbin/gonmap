package gonmap

import (
	"github.com/dlclark/regexp2"
	"testing"
)

func TestLoadNmapServiceProbes(t *testing.T) {
	probeList := LoadProbes(probes, 9)
	println(len(probeList))
}

func TestRegex(t *testing.T) {
	regex, err := regexp2.Compile(`^HTTP/[\d\.]{3} [\d]{3}`, 0)
	if err != nil {
		t.Fatal(err)
	}
	regex.GetGroupNumbers()
	m, err := regex.FindStringMatch("HTTP/1.1 200 OK\n")
	if err != nil {
		t.Fatal(err)
	}
	println(m.Groups())
}

func matchAll(probeList []*probe, banner []byte) *MatchResult {
	for _, p := range probeList {
		result := p.match(banner)
		if result != nil {
			return result
		}
	}
	return nil
}

func TestProbeMatch(t *testing.T) {
	probeList := LoadProbes(probes, 9)
	t.Logf("probe count: %d", len(probeList))
	tests := []struct {
		input    []byte
		expected struct {
			Service string
			Version string
		}
	}{
		{[]byte("HTTP/1.1 200 OK\r\n"), struct{ Service, Version string }{"http", ""}},
		{[]byte("J\x00\x00\x00\n8.0.36\x00\xb22\x00\x00n\x01Ak\x17\x13i\x1a\x00\xff\xff\xff\x02\x00\xff\xdf\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x12-Y\x15+\x0e`FvR\x038\x00caching_sha2_password\x00"),
			struct{ Service, Version string }{"mysql", "8.0.36"},
		}}
	for _, test := range tests {
		result := matchAll(probeList, test.input)
		if result == nil {
			t.Fatalf("match error for input: %s", test.input)
		}
		if result.Service != test.expected.Service {
			t.Fatalf("expected service %s, but got %s", test.expected.Service, result.Service)
		}
		if result.Version != test.expected.Version {
			t.Fatalf("expected server version %s, but got %s", test.expected.Version, result.Version)
		}
	}
}
