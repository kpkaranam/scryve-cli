package adapter_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/scryve/scryve/pkg/adapter"
)

// ---------------------------------------------------------------------------
// NucleiAdapter — ID / Name
// ---------------------------------------------------------------------------

func TestNucleiAdapter_IDAndName(t *testing.T) {
	a := adapter.NewNucleiAdapter()
	if a.ID() != adapter.AdapterIDNuclei {
		t.Errorf("ID() = %q, want %q", a.ID(), adapter.AdapterIDNuclei)
	}
	if a.Name() != "Nuclei" {
		t.Errorf("Name() = %q, want %q", a.Name(), "Nuclei")
	}
}

// ---------------------------------------------------------------------------
// NucleiAdapter — Check
// ---------------------------------------------------------------------------

func TestNucleiAdapter_Check_BinaryNotFound(t *testing.T) {
	a := adapter.NewNucleiAdapterWithBinary("/nonexistent/path/to/nuclei-missing")
	_, err := a.Check(context.Background())
	if err == nil {
		t.Fatal("expected error when binary not found, got nil")
	}
}

func TestNucleiAdapter_Check_ParsesVersion(t *testing.T) {
	src := `package main

import (
	"fmt"
	"os"
)

func main() {
	for _, arg := range os.Args[1:] {
		if arg == "-version" {
			fmt.Fprintln(os.Stderr, "Nuclei Engine Version: v3.1.0")
			os.Exit(0)
		}
	}
	os.Exit(0)
}
`
	binPath := buildFakeBinary(t, "nuclei", src)
	a := adapter.NewNucleiAdapterWithBinary(binPath)

	version, err := a.Check(context.Background())
	if err != nil {
		t.Fatalf("Check() unexpected error: %v", err)
	}
	if !strings.Contains(version, "v3") {
		t.Errorf("version %q does not contain expected prefix", version)
	}
}

// ---------------------------------------------------------------------------
// NucleiAdapter — Run: target selection
// ---------------------------------------------------------------------------

func TestNucleiAdapter_Run_UsesLiveHostsFirst(t *testing.T) {
	// Fake nuclei that reads targets from -l file and emits JSON findings.
	src := `package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	var listFile string
	for i, arg := range os.Args[1:] {
		if arg == "-l" && i+1 < len(os.Args[1:]) {
			listFile = os.Args[i+2]
		}
	}
	if listFile == "" {
		os.Exit(0)
	}
	f, err := os.Open(listFile)
	if err != nil {
		os.Exit(1)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		result := map[string]interface{}{
			"template-id": "test-template",
			"host":        line,
			"matched-at":  line,
			"type":        "http",
			"info": map[string]interface{}{
				"name":        "Test Finding",
				"severity":    "medium",
				"description": "test",
				"tags":        []string{"test"},
			},
		}
		b, _ := json.Marshal(result)
		fmt.Println(string(b))
	}
}
`
	binPath := buildFakeBinary(t, "nuclei", src)
	a := adapter.NewNucleiAdapterWithBinary(binPath)

	input := adapter.AdapterInput{
		LiveHosts:  []string{"https://live.example.com"},
		Subdomains: []string{"sub.example.com"},
		OpenPorts:  []string{"192.168.1.1:80"},
	}

	out, err := a.Run(context.Background(), input, adapter.AdapterConfig{}, nil)
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}

	// Should have used LiveHosts (1 target) producing 1 finding.
	if len(out.RawFindings) != 1 {
		t.Errorf("RawFindings count = %d, want 1", len(out.RawFindings))
	}
	if len(out.RawFindings) > 0 {
		host, _ := out.RawFindings[0].ToolOutput["host"].(string)
		if host != "https://live.example.com" {
			t.Errorf("host = %q, want %q", host, "https://live.example.com")
		}
	}
}

func TestNucleiAdapter_Run_FallsBackToSubdomains(t *testing.T) {
	src := `package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	var listFile string
	for i, arg := range os.Args[1:] {
		if arg == "-l" && i+1 < len(os.Args[1:]) {
			listFile = os.Args[i+2]
		}
	}
	if listFile == "" {
		os.Exit(0)
	}
	f, _ := os.Open(listFile)
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		result := map[string]interface{}{
			"template-id": "tmpl",
			"host":        line,
			"matched-at":  line,
			"type":        "dns",
			"info":        map[string]interface{}{"name": "DNS Finding", "severity": "info"},
		}
		b, _ := json.Marshal(result)
		fmt.Println(string(b))
	}
}
`
	binPath := buildFakeBinary(t, "nuclei", src)
	a := adapter.NewNucleiAdapterWithBinary(binPath)

	input := adapter.AdapterInput{
		LiveHosts:  []string{},
		Subdomains: []string{"sub.example.com", "api.example.com"},
	}

	out, err := a.Run(context.Background(), input, adapter.AdapterConfig{}, nil)
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}
	if len(out.RawFindings) != 2 {
		t.Errorf("RawFindings count = %d, want 2", len(out.RawFindings))
	}
}

func TestNucleiAdapter_Run_FallsBackToOpenPorts(t *testing.T) {
	src := `package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	var listFile string
	for i, arg := range os.Args[1:] {
		if arg == "-l" && i+1 < len(os.Args[1:]) {
			listFile = os.Args[i+2]
		}
	}
	if listFile == "" {
		os.Exit(0)
	}
	f, _ := os.Open(listFile)
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		result := map[string]interface{}{
			"template-id": "port-tmpl",
			"host":        line,
			"matched-at":  line,
			"type":        "tcp",
			"info":        map[string]interface{}{"name": "Port Finding", "severity": "low"},
		}
		b, _ := json.Marshal(result)
		fmt.Println(string(b))
	}
}
`
	binPath := buildFakeBinary(t, "nuclei", src)
	a := adapter.NewNucleiAdapterWithBinary(binPath)

	input := adapter.AdapterInput{
		LiveHosts:  []string{},
		Subdomains: []string{},
		OpenPorts:  []string{"10.0.0.1:443"},
	}

	out, err := a.Run(context.Background(), input, adapter.AdapterConfig{}, nil)
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}
	if len(out.RawFindings) != 1 {
		t.Errorf("RawFindings count = %d, want 1", len(out.RawFindings))
	}
}

func TestNucleiAdapter_Run_EmptyInput(t *testing.T) {
	a := adapter.NewNucleiAdapterWithBinary("/nonexistent/nuclei")

	out, err := a.Run(context.Background(), adapter.AdapterInput{}, adapter.AdapterConfig{}, nil)
	if err != nil {
		t.Fatalf("Run() with empty input should not error, got: %v", err)
	}
	if len(out.RawFindings) != 0 {
		t.Errorf("expected 0 findings for empty input, got %d", len(out.RawFindings))
	}
}

// ---------------------------------------------------------------------------
// NucleiAdapter — Run: JSON parsing
// ---------------------------------------------------------------------------

func TestNucleiAdapter_Run_ParsesJSONLines(t *testing.T) {
	src := `package main

import "fmt"

func main() {
	fmt.Println(` + "`" + `{"template-id":"cve-2021-41773","host":"https://target.example.com","matched-at":"https://target.example.com/cgi-bin/.%2F/bin/sh","type":"http","ip":"1.2.3.4","port":"443","info":{"name":"Apache Path Traversal","severity":"critical","description":"CVE-2021-41773","tags":["cve","apache"],"classification":{"cve-id":["CVE-2021-41773"],"cwe-id":["CWE-22"],"cvss-score":7.5,"cvss-metrics":"CVSS:3.1/AV:N"}}}` + "`" + `)
	fmt.Println(` + "`" + `{"template-id":"xss-reflected","host":"https://target.example.com","matched-at":"https://target.example.com/search?q=<script>","type":"http","info":{"name":"Reflected XSS","severity":"high"}}` + "`" + `)
	fmt.Println("not-json-at-all")
}
`
	binPath := buildFakeBinary(t, "nuclei", src)
	a := adapter.NewNucleiAdapterWithBinary(binPath)

	input := adapter.AdapterInput{LiveHosts: []string{"https://target.example.com"}}
	out, err := a.Run(context.Background(), input, adapter.AdapterConfig{}, nil)
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}
	if len(out.RawFindings) != 2 {
		t.Errorf("RawFindings count = %d, want 2", len(out.RawFindings))
	}
	for _, rf := range out.RawFindings {
		if rf.ToolName != string(adapter.AdapterIDNuclei) {
			t.Errorf("ToolName = %q, want %q", rf.ToolName, adapter.AdapterIDNuclei)
		}
	}
}

func TestNucleiAdapter_Run_SkipsInvalidJSON(t *testing.T) {
	src := `package main

import "fmt"

func main() {
	fmt.Println("garbage line 1")
	fmt.Println(` + "`" + `{"template-id":"test","host":"h","matched-at":"h","type":"http","info":{"name":"T","severity":"info"}}` + "`" + `)
	fmt.Println("{broken json")
}
`
	binPath := buildFakeBinary(t, "nuclei", src)
	a := adapter.NewNucleiAdapterWithBinary(binPath)

	input := adapter.AdapterInput{LiveHosts: []string{"h"}}
	out, err := a.Run(context.Background(), input, adapter.AdapterConfig{}, nil)
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}
	if len(out.RawFindings) != 1 {
		t.Errorf("RawFindings count = %d, want 1 (invalid JSON skipped)", len(out.RawFindings))
	}
}

// ---------------------------------------------------------------------------
// NucleiAdapter — Run: rate limit and extra args
// ---------------------------------------------------------------------------

func TestNucleiAdapter_Run_RateLimitPassed(t *testing.T) {
	src := `package main

import (
	"fmt"
	"os"
)

func main() {
	for i, arg := range os.Args {
		if arg == "-rl" && i+1 < len(os.Args) {
			fmt.Printf("rate=%s\n", os.Args[i+1])
			return
		}
	}
	fmt.Println("no-rate")
}
`
	binPath := buildFakeBinary(t, "nuclei", src)
	a := adapter.NewNucleiAdapterWithBinary(binPath)

	input := adapter.AdapterInput{LiveHosts: []string{"https://example.com"}}
	cfg := adapter.AdapterConfig{RateLimit: 50}
	// The binary prints non-JSON which gets skipped; we just verify no error.
	_, err := a.Run(context.Background(), input, cfg, nil)
	if err != nil {
		t.Fatalf("Run with rate limit: %v", err)
	}
}

func TestNucleiAdapter_Run_ExtraArgsPassed(t *testing.T) {
	src := `package main

import "fmt"

func main() {
	fmt.Println("{}")
}
`
	binPath := buildFakeBinary(t, "nuclei", src)
	a := adapter.NewNucleiAdapterWithBinary(binPath)

	input := adapter.AdapterInput{LiveHosts: []string{"https://example.com"}}
	cfg := adapter.AdapterConfig{ExtraArgs: []string{"-severity", "critical,high"}}
	_, err := a.Run(context.Background(), input, cfg, nil)
	if err != nil {
		t.Fatalf("Run with extra args: %v", err)
	}
}

// ---------------------------------------------------------------------------
// NucleiAdapter — Run: context / timeout
// ---------------------------------------------------------------------------

func TestNucleiAdapter_Run_ContextCancellation(t *testing.T) {
	src := `package main

import (
	"fmt"
	"os"
	"time"
)

func main() {
	fmt.Fprintln(os.Stderr, "blocking nuclei stub")
	time.Sleep(10 * time.Minute)
}
`
	binPath := buildFakeBinary(t, "nuclei", src)
	a := adapter.NewNucleiAdapterWithBinary(binPath)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	input := adapter.AdapterInput{LiveHosts: []string{"https://example.com"}}
	_, err := a.Run(ctx, input, adapter.AdapterConfig{}, nil)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		if !strings.Contains(err.Error(), "killed") && !strings.Contains(err.Error(), "signal") && !strings.Contains(err.Error(), "context") {
			t.Errorf("unexpected error: %v", err)
		}
	}
}

func TestNucleiAdapter_Run_ConfigTimeout(t *testing.T) {
	src := `package main

import (
	"fmt"
	"os"
	"time"
)

func main() {
	fmt.Fprintln(os.Stderr, "blocking nuclei stub")
	time.Sleep(10 * time.Minute)
}
`
	binPath := buildFakeBinary(t, "nuclei", src)
	a := adapter.NewNucleiAdapterWithBinary(binPath)

	cfg := adapter.AdapterConfig{Timeout: 200 * time.Millisecond}
	input := adapter.AdapterInput{LiveHosts: []string{"https://example.com"}}
	_, err := a.Run(context.Background(), input, cfg, nil)
	if err == nil {
		t.Fatal("expected cfg.Timeout error, got nil")
	}
}

// ---------------------------------------------------------------------------
// NucleiAdapter — Run: progress writer
// ---------------------------------------------------------------------------

func TestNucleiAdapter_Run_WritesProgress(t *testing.T) {
	src := `package main

import "fmt"

func main() {
	fmt.Println(` + "`" + `{"template-id":"test","host":"https://example.com","matched-at":"https://example.com","type":"http","info":{"name":"Test","severity":"info"}}` + "`" + `)
}
`
	binPath := buildFakeBinary(t, "nuclei", src)
	a := adapter.NewNucleiAdapterWithBinary(binPath)

	input := adapter.AdapterInput{LiveHosts: []string{"https://example.com"}}
	var buf strings.Builder
	_, err := a.Run(context.Background(), input, adapter.AdapterConfig{}, &buf)
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("expected progress output, got empty buffer")
	}
}

// ---------------------------------------------------------------------------
// NucleiAdapter — global registration
// ---------------------------------------------------------------------------

func TestNucleiAdapter_GlobalRegistration(t *testing.T) {
	a, err := adapter.Get(adapter.AdapterIDNuclei)
	if err != nil {
		t.Fatalf("global registry does not contain nuclei adapter: %v", err)
	}
	if a.ID() != adapter.AdapterIDNuclei {
		t.Errorf("registered adapter ID = %q, want %q", a.ID(), adapter.AdapterIDNuclei)
	}
}

// ---------------------------------------------------------------------------
// ParseNucleiLine — typed struct parsing
// ---------------------------------------------------------------------------

func TestParseNucleiLine_FullResult(t *testing.T) {
	line := []byte(`{
		"template-id": "cve-2021-41773",
		"host": "https://target.example.com",
		"matched-at": "https://target.example.com/cgi-bin/.%2F/bin/sh",
		"type": "http",
		"ip": "1.2.3.4",
		"port": "443",
		"matcher-name": "root-rce",
		"extracted-results": ["uid=0(root)"],
		"curl-command": "curl https://target.example.com/cgi-bin/.%2F/bin/sh",
		"info": {
			"name": "Apache Path Traversal RCE",
			"severity": "critical",
			"description": "CVE-2021-41773 in Apache HTTP Server",
			"tags": ["cve", "apache", "rce"],
			"classification": {
				"cve-id": ["CVE-2021-41773"],
				"cwe-id": ["CWE-22"],
				"cvss-score": 9.8,
				"cvss-metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
			}
		}
	}`)

	result, err := adapter.ParseNucleiLine(line)
	if err != nil {
		t.Fatalf("ParseNucleiLine() error: %v", err)
	}

	if result.TemplateID != "cve-2021-41773" {
		t.Errorf("TemplateID = %q, want %q", result.TemplateID, "cve-2021-41773")
	}
	if result.Host != "https://target.example.com" {
		t.Errorf("Host = %q, want %q", result.Host, "https://target.example.com")
	}
	if result.MatchedAt != "https://target.example.com/cgi-bin/.%2F/bin/sh" {
		t.Errorf("MatchedAt = %q", result.MatchedAt)
	}
	if result.Type != "http" {
		t.Errorf("Type = %q, want %q", result.Type, "http")
	}
	if result.IP != "1.2.3.4" {
		t.Errorf("IP = %q, want %q", result.IP, "1.2.3.4")
	}
	if result.Port != "443" {
		t.Errorf("Port = %q, want %q", result.Port, "443")
	}
	if result.MatcherName != "root-rce" {
		t.Errorf("MatcherName = %q, want %q", result.MatcherName, "root-rce")
	}
	if len(result.ExtractedResults) != 1 || result.ExtractedResults[0] != "uid=0(root)" {
		t.Errorf("ExtractedResults = %v", result.ExtractedResults)
	}
	if result.CurlCommand == "" {
		t.Error("CurlCommand should not be empty")
	}

	// Info fields
	if result.Info.Name != "Apache Path Traversal RCE" {
		t.Errorf("Info.Name = %q", result.Info.Name)
	}
	if result.Info.Severity != "critical" {
		t.Errorf("Info.Severity = %q, want %q", result.Info.Severity, "critical")
	}
	if result.Info.Description == "" {
		t.Error("Info.Description should not be empty")
	}
	if len(result.Info.Tags) != 3 {
		t.Errorf("Info.Tags = %v, want 3 items", result.Info.Tags)
	}

	// Classification
	if len(result.Info.Classification.CVEID) != 1 || result.Info.Classification.CVEID[0] != "CVE-2021-41773" {
		t.Errorf("Classification.CVEID = %v", result.Info.Classification.CVEID)
	}
	if len(result.Info.Classification.CWEID) != 1 || result.Info.Classification.CWEID[0] != "CWE-22" {
		t.Errorf("Classification.CWEID = %v", result.Info.Classification.CWEID)
	}
	if result.Info.Classification.CVSSScore != 9.8 {
		t.Errorf("Classification.CVSSScore = %v, want 9.8", result.Info.Classification.CVSSScore)
	}
	if result.Info.Classification.CVSSMetrics == "" {
		t.Error("Classification.CVSSMetrics should not be empty")
	}
}

func TestParseNucleiLine_MinimalResult(t *testing.T) {
	line := []byte(`{"template-id":"test","host":"example.com","matched-at":"example.com","type":"dns","info":{"name":"Test","severity":"info"}}`)

	result, err := adapter.ParseNucleiLine(line)
	if err != nil {
		t.Fatalf("ParseNucleiLine() error: %v", err)
	}
	if result.TemplateID != "test" {
		t.Errorf("TemplateID = %q, want %q", result.TemplateID, "test")
	}
	if result.Info.Severity != "info" {
		t.Errorf("Info.Severity = %q, want %q", result.Info.Severity, "info")
	}
}

func TestParseNucleiLine_InvalidJSON(t *testing.T) {
	_, err := adapter.ParseNucleiLine([]byte("not-json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestParseNucleiLine_EmptyLine(t *testing.T) {
	_, err := adapter.ParseNucleiLine([]byte(""))
	if err == nil {
		t.Fatal("expected error for empty line, got nil")
	}
}

// ---------------------------------------------------------------------------
// NucleiAdapter — AdapterOutput fields
// ---------------------------------------------------------------------------

func TestNucleiAdapter_Run_OutputFields(t *testing.T) {
	src := `package main

import "fmt"

func main() {
	fmt.Println(` + "`" + `{"template-id":"sqli","host":"https://app.example.com","matched-at":"https://app.example.com/login","type":"http","info":{"name":"SQL Injection","severity":"high"}}` + "`" + `)
}
`
	binPath := buildFakeBinary(t, "nuclei", src)
	a := adapter.NewNucleiAdapterWithBinary(binPath)

	input := adapter.AdapterInput{LiveHosts: []string{"https://app.example.com"}}
	out, err := a.Run(context.Background(), input, adapter.AdapterConfig{}, nil)
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}

	if out.AdapterID != adapter.AdapterIDNuclei {
		t.Errorf("AdapterID = %q, want %q", out.AdapterID, adapter.AdapterIDNuclei)
	}
	if len(out.RawFindings) != 1 {
		t.Fatalf("RawFindings count = %d, want 1", len(out.RawFindings))
	}
	rf := out.RawFindings[0]
	if rf.ToolName != string(adapter.AdapterIDNuclei) {
		t.Errorf("ToolName = %q, want %q", rf.ToolName, adapter.AdapterIDNuclei)
	}
}
