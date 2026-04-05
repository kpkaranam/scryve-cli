package email_test

import (
	"context"
	"errors"
	"testing"

	"github.com/scryve/scryve/pkg/email"
)

// ---------------------------------------------------------------------------
// CheckDMARC — record not found
// ---------------------------------------------------------------------------

func TestCheckDMARC_NoRecord(t *testing.T) {
	r := NewMockResolver()
	result := email.CheckDMARC(context.Background(), "example.com", r)

	if result.Found {
		t.Error("Found should be false when no DMARC record exists")
	}
	if result.Policy != email.DMARCPolicyMissing {
		t.Errorf("Policy = %q, want %q", result.Policy, email.DMARCPolicyMissing)
	}
	if result.Error != nil {
		t.Errorf("Error should be nil, got: %v", result.Error)
	}
}

// ---------------------------------------------------------------------------
// CheckDMARC — policy parsing
// ---------------------------------------------------------------------------

func TestCheckDMARC_PolicyNone(t *testing.T) {
	r := NewMockResolver()
	r.SetTXT("_dmarc.example.com", "v=DMARC1; p=none; rua=mailto:dmarc@example.com")

	result := email.CheckDMARC(context.Background(), "example.com", r)

	if !result.Found {
		t.Fatal("Found should be true")
	}
	if result.Policy != email.DMARCPolicyNone {
		t.Errorf("Policy = %q, want %q", result.Policy, email.DMARCPolicyNone)
	}
	if result.IsEnforced() {
		t.Error("IsEnforced() should be false for p=none")
	}
}

func TestCheckDMARC_PolicyQuarantine(t *testing.T) {
	r := NewMockResolver()
	r.SetTXT("_dmarc.example.com", "v=DMARC1; p=quarantine; pct=50")

	result := email.CheckDMARC(context.Background(), "example.com", r)

	if result.Policy != email.DMARCPolicyQuarantine {
		t.Errorf("Policy = %q, want %q", result.Policy, email.DMARCPolicyQuarantine)
	}
	if !result.IsEnforced() {
		t.Error("IsEnforced() should be true for p=quarantine")
	}
	if result.Pct != 50 {
		t.Errorf("Pct = %d, want 50", result.Pct)
	}
}

func TestCheckDMARC_PolicyReject(t *testing.T) {
	r := NewMockResolver()
	r.SetTXT("_dmarc.example.com", "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; ruf=mailto:dmarc-failures@example.com")

	result := email.CheckDMARC(context.Background(), "example.com", r)

	if result.Policy != email.DMARCPolicyReject {
		t.Errorf("Policy = %q, want %q", result.Policy, email.DMARCPolicyReject)
	}
	if !result.IsEnforced() {
		t.Error("IsEnforced() should be true for p=reject")
	}
}

// ---------------------------------------------------------------------------
// CheckDMARC — pct field
// ---------------------------------------------------------------------------

func TestCheckDMARC_DefaultPct100(t *testing.T) {
	r := NewMockResolver()
	r.SetTXT("_dmarc.example.com", "v=DMARC1; p=reject")

	result := email.CheckDMARC(context.Background(), "example.com", r)

	if result.Pct != 100 {
		t.Errorf("Pct = %d, want 100 (default)", result.Pct)
	}
}

func TestCheckDMARC_PctParsed(t *testing.T) {
	r := NewMockResolver()
	r.SetTXT("_dmarc.example.com", "v=DMARC1; p=quarantine; pct=25")

	result := email.CheckDMARC(context.Background(), "example.com", r)

	if result.Pct != 25 {
		t.Errorf("Pct = %d, want 25", result.Pct)
	}
}

// ---------------------------------------------------------------------------
// CheckDMARC — subdomain policy
// ---------------------------------------------------------------------------

func TestCheckDMARC_SubdomainPolicyInherited(t *testing.T) {
	r := NewMockResolver()
	r.SetTXT("_dmarc.example.com", "v=DMARC1; p=reject")

	result := email.CheckDMARC(context.Background(), "example.com", r)

	// sp= absent → inherits p=
	if result.SubdomainPolicy != email.DMARCPolicyReject {
		t.Errorf("SubdomainPolicy = %q, want %q (inherited from p=)", result.SubdomainPolicy, email.DMARCPolicyReject)
	}
}

func TestCheckDMARC_SubdomainPolicyExplicit(t *testing.T) {
	r := NewMockResolver()
	r.SetTXT("_dmarc.example.com", "v=DMARC1; p=reject; sp=none")

	result := email.CheckDMARC(context.Background(), "example.com", r)

	if result.SubdomainPolicy != email.DMARCPolicyNone {
		t.Errorf("SubdomainPolicy = %q, want %q", result.SubdomainPolicy, email.DMARCPolicyNone)
	}
}

// ---------------------------------------------------------------------------
// CheckDMARC — reporting URIs
// ---------------------------------------------------------------------------

func TestCheckDMARC_RUAFParsed(t *testing.T) {
	r := NewMockResolver()
	r.SetTXT("_dmarc.example.com", "v=DMARC1; p=none; rua=mailto:a@example.com,mailto:b@example.com")

	result := email.CheckDMARC(context.Background(), "example.com", r)

	if len(result.RUAF) != 2 {
		t.Errorf("RUAF = %v, want 2 entries", result.RUAF)
	}
}

func TestCheckDMARC_RUFSParsed(t *testing.T) {
	r := NewMockResolver()
	r.SetTXT("_dmarc.example.com", "v=DMARC1; p=none; ruf=mailto:failures@example.com")

	result := email.CheckDMARC(context.Background(), "example.com", r)

	if len(result.RUFS) != 1 {
		t.Errorf("RUFS = %v, want 1 entry", result.RUFS)
	}
}

// ---------------------------------------------------------------------------
// CheckDMARC — record preserved
// ---------------------------------------------------------------------------

func TestCheckDMARC_RecordPreserved(t *testing.T) {
	raw := "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
	r := NewMockResolver()
	r.SetTXT("_dmarc.example.com", raw)

	result := email.CheckDMARC(context.Background(), "example.com", r)

	if result.Record != raw {
		t.Errorf("Record = %q, want %q", result.Record, raw)
	}
}

// ---------------------------------------------------------------------------
// CheckDMARC — DNS error handling
// ---------------------------------------------------------------------------

func TestCheckDMARC_DNSError(t *testing.T) {
	r := NewMockResolver()
	r.SetError("_dmarc.example.com", errors.New("connection refused"))

	result := email.CheckDMARC(context.Background(), "example.com", r)

	if result.Error == nil {
		t.Error("expected Error to be set on DNS failure")
	}
	if result.Found {
		t.Error("Found should be false on DNS error")
	}
}

// ---------------------------------------------------------------------------
// CheckDMARC — case insensitivity
// ---------------------------------------------------------------------------

func TestCheckDMARC_CaseInsensitive(t *testing.T) {
	r := NewMockResolver()
	r.SetTXT("_dmarc.example.com", "V=DMARC1; P=REJECT")

	result := email.CheckDMARC(context.Background(), "example.com", r)

	if !result.Found {
		t.Error("DMARC record should be found regardless of case")
	}
	if result.Policy != email.DMARCPolicyReject {
		t.Errorf("Policy = %q, want %q", result.Policy, email.DMARCPolicyReject)
	}
}
