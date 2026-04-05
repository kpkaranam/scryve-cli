package email_test

import (
	"context"
	"strings"
	"testing"

	"github.com/scryve/scryve/pkg/adapter"
	"github.com/scryve/scryve/pkg/email"
)

// ---------------------------------------------------------------------------
// CheckDomain — convenience aggregate
// ---------------------------------------------------------------------------

func TestCheckDomain_AllChecksRun(t *testing.T) {
	r := NewMockResolver()
	r.SetTXT("example.com", "v=spf1 -all")
	r.SetTXT("_dmarc.example.com", "v=DMARC1; p=reject")
	r.SetTXT("google._domainkey.example.com", "v=DKIM1; k=rsa; p=abc123")

	result := email.CheckDomain(context.Background(), "example.com", r)

	if result.Domain != "example.com" {
		t.Errorf("Domain = %q, want %q", result.Domain, "example.com")
	}
	if !result.SPF.Found {
		t.Error("SPF.Found should be true")
	}
	if !result.DKIM.Found {
		t.Error("DKIM.Found should be true")
	}
	if !result.DMARC.Found {
		t.Error("DMARC.Found should be true")
	}
}

func TestCheckDomain_EmptyDomain(t *testing.T) {
	r := NewMockResolver()
	// Empty domain → checks run but find nothing (no DNS records configured).
	result := email.CheckDomain(context.Background(), "", r)
	if result.SPF.Error != nil {
		// An error is acceptable for empty domain, but Found should be false.
		t.Logf("SPF.Error = %v (acceptable for empty domain)", result.SPF.Error)
	}
}

// ---------------------------------------------------------------------------
// EmailAdapter — ID / Name / Check
// ---------------------------------------------------------------------------

func TestEmailAdapter_IDAndName(t *testing.T) {
	a := email.NewEmailAdapterWithResolver(NewMockResolver())
	if a.ID() != adapter.AdapterIDEmail {
		t.Errorf("ID() = %q, want %q", a.ID(), adapter.AdapterIDEmail)
	}
	if a.Name() != "Email Security" {
		t.Errorf("Name() = %q, want %q", a.Name(), "Email Security")
	}
}

func TestEmailAdapter_Check_Succeeds(t *testing.T) {
	a := email.NewEmailAdapterWithResolver(NewMockResolver())
	version, err := a.Check(context.Background())
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if version == "" {
		t.Error("version should not be empty")
	}
}

// ---------------------------------------------------------------------------
// EmailAdapter — Run
// ---------------------------------------------------------------------------

func TestEmailAdapter_Run_EmptyDomain(t *testing.T) {
	a := email.NewEmailAdapterWithResolver(NewMockResolver())
	out, err := a.Run(context.Background(), adapter.AdapterInput{}, adapter.AdapterConfig{}, nil)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if len(out.RawFindings) != 0 {
		t.Errorf("expected 0 findings for empty domain, got %d", len(out.RawFindings))
	}
}

func TestEmailAdapter_Run_ProducesThreeFindings(t *testing.T) {
	r := NewMockResolver()
	r.SetTXT("example.com", "v=spf1 -all")
	r.SetTXT("_dmarc.example.com", "v=DMARC1; p=reject")

	a := email.NewEmailAdapterWithResolver(r)
	out, err := a.Run(context.Background(), adapter.AdapterInput{Domain: "example.com"}, adapter.AdapterConfig{}, nil)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	// Should produce exactly 3 findings: SPF, DKIM, DMARC.
	if len(out.RawFindings) != 3 {
		t.Errorf("RawFindings count = %d, want 3", len(out.RawFindings))
	}
}

func TestEmailAdapter_Run_FindingsHaveCorrectToolName(t *testing.T) {
	r := NewMockResolver()
	a := email.NewEmailAdapterWithResolver(r)
	out, err := a.Run(context.Background(), adapter.AdapterInput{Domain: "example.com"}, adapter.AdapterConfig{}, nil)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	for _, rf := range out.RawFindings {
		if rf.ToolName != string(adapter.AdapterIDEmail) {
			t.Errorf("ToolName = %q, want %q", rf.ToolName, adapter.AdapterIDEmail)
		}
	}
}

func TestEmailAdapter_Run_AdapterIDSet(t *testing.T) {
	r := NewMockResolver()
	a := email.NewEmailAdapterWithResolver(r)
	out, err := a.Run(context.Background(), adapter.AdapterInput{Domain: "example.com"}, adapter.AdapterConfig{}, nil)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if out.AdapterID != adapter.AdapterIDEmail {
		t.Errorf("AdapterID = %q, want %q", out.AdapterID, adapter.AdapterIDEmail)
	}
}

func TestEmailAdapter_Run_FindingsContainCheckField(t *testing.T) {
	r := NewMockResolver()
	a := email.NewEmailAdapterWithResolver(r)
	out, err := a.Run(context.Background(), adapter.AdapterInput{Domain: "example.com"}, adapter.AdapterConfig{}, nil)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	checks := make(map[string]bool)
	for _, rf := range out.RawFindings {
		check, _ := rf.ToolOutput["check"].(string)
		checks[check] = true
	}

	for _, want := range []string{"spf", "dkim", "dmarc"} {
		if !checks[want] {
			t.Errorf("missing finding with check=%q", want)
		}
	}
}

func TestEmailAdapter_Run_WritesProgress(t *testing.T) {
	r := NewMockResolver()
	a := email.NewEmailAdapterWithResolver(r)

	var buf strings.Builder
	_, err := a.Run(context.Background(), adapter.AdapterInput{Domain: "example.com"}, adapter.AdapterConfig{}, &buf)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("expected progress output, got empty buffer")
	}
	if !strings.Contains(buf.String(), "example.com") {
		t.Errorf("progress should mention domain, got: %q", buf.String())
	}
}

// ---------------------------------------------------------------------------
// EmailAdapter — global registration
// ---------------------------------------------------------------------------

func TestEmailAdapter_GlobalRegistration(t *testing.T) {
	a, err := adapter.Get(adapter.AdapterIDEmail)
	if err != nil {
		t.Fatalf("global registry does not contain email adapter: %v", err)
	}
	if a.ID() != adapter.AdapterIDEmail {
		t.Errorf("registered adapter ID = %q, want %q", a.ID(), adapter.AdapterIDEmail)
	}
}

// ---------------------------------------------------------------------------
// EmailAdapter — SPF finding structure
// ---------------------------------------------------------------------------

func TestEmailAdapter_Run_SPFFindingStrict(t *testing.T) {
	r := NewMockResolver()
	r.SetTXT("example.com", "v=spf1 -all")

	a := email.NewEmailAdapterWithResolver(r)
	out, _ := a.Run(context.Background(), adapter.AdapterInput{Domain: "example.com"}, adapter.AdapterConfig{}, nil)

	for _, rf := range out.RawFindings {
		check, _ := rf.ToolOutput["check"].(string)
		if check != "spf" {
			continue
		}
		if strict, ok := rf.ToolOutput["is_strict"].(bool); !ok || !strict {
			t.Error("SPF finding: is_strict should be true for -all policy")
		}
		return
	}
	t.Error("SPF finding not found")
}

// ---------------------------------------------------------------------------
// EmailAdapter — DMARC finding structure
// ---------------------------------------------------------------------------

func TestEmailAdapter_Run_DMARCFindingEnforced(t *testing.T) {
	r := NewMockResolver()
	r.SetTXT("_dmarc.example.com", "v=DMARC1; p=reject")

	a := email.NewEmailAdapterWithResolver(r)
	out, _ := a.Run(context.Background(), adapter.AdapterInput{Domain: "example.com"}, adapter.AdapterConfig{}, nil)

	for _, rf := range out.RawFindings {
		check, _ := rf.ToolOutput["check"].(string)
		if check != "dmarc" {
			continue
		}
		if enforced, ok := rf.ToolOutput["is_enforced"].(bool); !ok || !enforced {
			t.Error("DMARC finding: is_enforced should be true for p=reject")
		}
		return
	}
	t.Error("DMARC finding not found")
}
