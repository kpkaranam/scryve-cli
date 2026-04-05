package email_test

import (
	"context"
	"errors"
	"testing"

	"github.com/scryve/scryve/pkg/email"
)

// ---------------------------------------------------------------------------
// CheckDKIM — no selectors found
// ---------------------------------------------------------------------------

func TestCheckDKIM_NoSelectors(t *testing.T) {
	r := NewMockResolver()
	// No DKIM records at all.
	result := email.CheckDKIM(context.Background(), "example.com", r)

	if result.Found {
		t.Error("Found should be false when no DKIM selectors exist")
	}
	if result.Error != nil {
		t.Errorf("Error should be nil, got: %v", result.Error)
	}
	if len(result.Selectors) == 0 {
		t.Error("Selectors slice should be non-empty (probed selectors logged)")
	}
}

// ---------------------------------------------------------------------------
// CheckDKIM — selector found
// ---------------------------------------------------------------------------

func TestCheckDKIM_GoogleSelectorFound(t *testing.T) {
	r := NewMockResolver()
	// Simulate a google DKIM selector record.
	r.SetTXT("google._domainkey.example.com",
		"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2a7tMK7Sx9FzF5Tp1U+fVl6MCKuCNQJ2MN7rStFFHm9RNDO0ysepblNOqBJMSPYIXLv0Y7V3yXKGkqcLrPEAJ0pHHk9PRLVdkDR8C1+PNz+e4GxHN")

	result := email.CheckDKIM(context.Background(), "example.com", r)

	if !result.Found {
		t.Fatal("Found should be true when a DKIM record exists")
	}

	var googleSel *email.DKIMSelectorResult
	for i := range result.Selectors {
		if result.Selectors[i].Selector == "google" && result.Selectors[i].Found {
			googleSel = &result.Selectors[i]
			break
		}
	}
	if googleSel == nil {
		t.Fatal("expected google selector to be found")
	}
	if googleSel.Record == "" {
		t.Error("Record should not be empty for a found selector")
	}
}

func TestCheckDKIM_KeyLength2048(t *testing.T) {
	r := NewMockResolver()
	// A long p= value (>380 chars base64) should be estimated as 2048-bit.
	longKey := "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2a7tMK7Sx9FzF5Tp1U+fVl6MCKuCNQJ2MN7rStFFHm9RNDO0ysepblNOqBJMSPYIXLv0Y7V3yXKGkqcLrPEAJ0pHHk9PRLVdkDR8C1+PNz+e4GxHNVqTpELbX2S0Jd6zP9O8wMsJkQ7f3XQkC5RpYH8g4k2sM1nKfAh3rOJ5YKRLWxuX4b8N7mCkP5sVQ1XJo4tEyLv2A3I6Nl9zOwMEi7pTh8dR5Bq1YmW0KJFsHg6uCvA2bP9nXeT3ZkGl8hUq0yMrD5wNjVKE7sXp1OaL4mBR2CnFd6Yv8tQ"
	r.SetTXT("selector1._domainkey.example.com", "v=DKIM1; k=rsa; p="+longKey)

	result := email.CheckDKIM(context.Background(), "example.com", r)

	if !result.Found {
		t.Fatal("Found should be true")
	}
	for _, sel := range result.Selectors {
		if sel.Selector == "selector1" && sel.Found {
			if sel.KeyLength != 2048 {
				t.Errorf("KeyLength = %d, want 2048", sel.KeyLength)
			}
			return
		}
	}
	t.Error("selector1 not found in results")
}

func TestCheckDKIM_KeyLength1024(t *testing.T) {
	r := NewMockResolver()
	// A medium p= value (~216 chars) should be estimated as 1024-bit.
	medKey := "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCrZ5yJXLGg3GRmDSR4oFO9FxnBUDnJU2GQH5pBXJ7fRhQyLT3VNrNT3Z1z5Y4h8q0JoKpZ7sQkN2RwMnV9JkRk6M0Q"
	r.SetTXT("mail._domainkey.example.com", "v=DKIM1; k=rsa; p="+medKey)

	result := email.CheckDKIM(context.Background(), "example.com", r)

	for _, sel := range result.Selectors {
		if sel.Selector == "mail" && sel.Found {
			if sel.KeyLength != 1024 {
				t.Errorf("KeyLength = %d, want 1024", sel.KeyLength)
			}
			return
		}
	}
	t.Error("mail selector not found in results")
}

func TestCheckDKIM_MultipleSelectorsFound(t *testing.T) {
	r := NewMockResolver()
	r.SetTXT("default._domainkey.example.com", "v=DKIM1; k=rsa; p=abc123")
	r.SetTXT("mail._domainkey.example.com", "v=DKIM1; k=rsa; p=def456")

	result := email.CheckDKIM(context.Background(), "example.com", r)

	if !result.Found {
		t.Fatal("Found should be true")
	}

	foundCount := 0
	for _, sel := range result.Selectors {
		if sel.Found {
			foundCount++
		}
	}
	if foundCount != 2 {
		t.Errorf("found %d selectors, want 2", foundCount)
	}
}

// ---------------------------------------------------------------------------
// CheckDKIM — record without v=DKIM1 but with p= still matches
// ---------------------------------------------------------------------------

func TestCheckDKIM_RecordWithPEqualOnly(t *testing.T) {
	r := NewMockResolver()
	r.SetTXT("k1._domainkey.example.com", "k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUA")

	result := email.CheckDKIM(context.Background(), "example.com", r)

	for _, sel := range result.Selectors {
		if sel.Selector == "k1" {
			if !sel.Found {
				t.Error("k1 selector should be found (record has p= field)")
			}
			return
		}
	}
	t.Error("k1 selector not in results")
}

// ---------------------------------------------------------------------------
// CheckDKIM — DNS error for a selector is non-fatal
// ---------------------------------------------------------------------------

func TestCheckDKIM_DNSErrorForOneSelectorContinues(t *testing.T) {
	r := NewMockResolver()
	r.SetError("default._domainkey.example.com", errors.New("timeout"))
	r.SetTXT("google._domainkey.example.com", "v=DKIM1; k=rsa; p=abc")

	result := email.CheckDKIM(context.Background(), "example.com", r)

	// Overall result should still be Found=true because google selector succeeded.
	if !result.Found {
		t.Error("Found should be true when at least one selector succeeds")
	}
	if result.Error != nil {
		t.Error("top-level Error should be nil; per-selector errors are absorbed")
	}
}

// ---------------------------------------------------------------------------
// CheckDKIM — all 9 selectors are probed
// ---------------------------------------------------------------------------

func TestCheckDKIM_AllNineSelectorsProbed(t *testing.T) {
	r := NewMockResolver()
	result := email.CheckDKIM(context.Background(), "example.com", r)

	// Should probe all 9 common selectors.
	if len(result.Selectors) != 9 {
		t.Errorf("expected 9 selector results, got %d", len(result.Selectors))
	}
}
