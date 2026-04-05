// Package email — EmailAdapter wiring for the Scryve adapter pipeline.
//
// EmailAdapter implements adapter.Adapter so that email security checks
// (SPF, DKIM, DMARC) can be driven by the same pipeline machinery as all
// other security tool adapters.
package email

import (
	"context"
	"fmt"
	"io"

	"github.com/scryve/scryve/pkg/adapter"
)

// ---------------------------------------------------------------------------
// DomainResult — convenience aggregate
// ---------------------------------------------------------------------------

// DomainResult bundles the SPF, DKIM, and DMARC results for a single domain.
type DomainResult struct {
	// Domain is the target domain that was checked.
	Domain string

	// SPF holds the SPF check result.
	SPF SPFResult

	// DKIM holds the DKIM check result.
	DKIM DKIMResult

	// DMARC holds the DMARC check result.
	DMARC DMARCResult
}

// CheckDomain runs SPF, DKIM, and DMARC checks for domain in parallel
// (serially in this implementation) using the provided resolver.
//
// This is a convenience wrapper intended for use outside the full adapter
// pipeline (e.g. in tests or one-off CLI commands).
func CheckDomain(ctx context.Context, domain string, resolver Resolver) DomainResult {
	return DomainResult{
		Domain: domain,
		SPF:    CheckSPF(ctx, domain, resolver),
		DKIM:   CheckDKIM(ctx, domain, resolver),
		DMARC:  CheckDMARC(ctx, domain, resolver),
	}
}

// ---------------------------------------------------------------------------
// EmailAdapter
// ---------------------------------------------------------------------------

// EmailAdapter implements adapter.Adapter for email security checks.
// It drives SPF, DKIM, and DMARC checks for the domain in AdapterInput.
type EmailAdapter struct {
	resolver Resolver
}

// NewEmailAdapter returns an EmailAdapter that uses the system DNS resolver.
func NewEmailAdapter() *EmailAdapter {
	return &EmailAdapter{resolver: DefaultResolver()}
}

// NewEmailAdapterWithResolver returns an EmailAdapter that uses the provided
// resolver.  Use this constructor in tests to inject a mock resolver.
func NewEmailAdapterWithResolver(r Resolver) *EmailAdapter {
	return &EmailAdapter{resolver: r}
}

// init registers the EmailAdapter with the global adapter registry.
func init() {
	adapter.Register(NewEmailAdapter())
}

// ---------------------------------------------------------------------------
// adapter.Adapter interface
// ---------------------------------------------------------------------------

// ID returns adapter.AdapterIDEmail.
func (a *EmailAdapter) ID() adapter.AdapterID {
	return adapter.AdapterIDEmail
}

// Name returns "Email Security".
func (a *EmailAdapter) Name() string {
	return "Email Security"
}

// Check verifies that the adapter is functional.  Since the email adapter
// uses pure DNS (no external binary), this always returns a static version
// string as long as the resolver itself is non-nil.
func (a *EmailAdapter) Check(_ context.Context) (string, error) {
	if a.resolver == nil {
		return "", fmt.Errorf("email: resolver is nil")
	}
	return "v1.0.0-email-security", nil
}

// Run performs SPF, DKIM, and DMARC checks for input.Domain and returns
// structured RawFindings.  Each check produces one RawFinding whose
// ToolOutput map mirrors the check result fields.
//
// Progress messages are written to progressWriter when non-nil.
func (a *EmailAdapter) Run(ctx context.Context, input adapter.AdapterInput, _ adapter.AdapterConfig, progressWriter io.Writer) (adapter.AdapterOutput, error) {
	if input.Domain == "" {
		return adapter.AdapterOutput{AdapterID: adapter.AdapterIDEmail}, nil
	}

	if progressWriter != nil {
		fmt.Fprintf(progressWriter, "[email] Checking email security for %s\n", input.Domain)
	}

	result := CheckDomain(ctx, input.Domain, a.resolver)
	findings := a.buildFindings(result)

	if progressWriter != nil {
		fmt.Fprintf(progressWriter, "[email] Completed: SPF=%v DKIM=%v DMARC=%v\n",
			result.SPF.Found, result.DKIM.Found, result.DMARC.Found)
	}

	return adapter.AdapterOutput{
		AdapterID:   adapter.AdapterIDEmail,
		RawFindings: findings,
	}, nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// buildFindings converts a DomainResult into adapter.RawFinding records.
// Each of SPF, DKIM, and DMARC produces one finding regardless of outcome,
// so the pipeline always has a complete picture.
func (a *EmailAdapter) buildFindings(result DomainResult) []adapter.RawFinding {
	var findings []adapter.RawFinding

	// SPF finding.
	spfOutput := map[string]interface{}{
		"check":         "spf",
		"domain":        result.Domain,
		"found":         result.SPF.Found,
		"record":        result.SPF.Record,
		"policy":        string(result.SPF.Policy),
		"include_count": result.SPF.IncludeCount,
		"is_strict":     result.SPF.IsStrict(),
	}
	if result.SPF.Error != nil {
		spfOutput["error"] = result.SPF.Error.Error()
	}
	findings = append(findings, adapter.RawFinding{
		ToolName:   string(adapter.AdapterIDEmail),
		ToolOutput: spfOutput,
	})

	// DKIM finding.
	selectors := make([]interface{}, 0, len(result.DKIM.Selectors))
	for _, s := range result.DKIM.Selectors {
		if s.Found {
			selectors = append(selectors, map[string]interface{}{
				"selector":   s.Selector,
				"found":      s.Found,
				"key_length": s.KeyLength,
			})
		}
	}
	dkimOutput := map[string]interface{}{
		"check":     "dkim",
		"domain":    result.Domain,
		"found":     result.DKIM.Found,
		"selectors": selectors,
	}
	if result.DKIM.Error != nil {
		dkimOutput["error"] = result.DKIM.Error.Error()
	}
	findings = append(findings, adapter.RawFinding{
		ToolName:   string(adapter.AdapterIDEmail),
		ToolOutput: dkimOutput,
	})

	// DMARC finding.
	dmarcOutput := map[string]interface{}{
		"check":            "dmarc",
		"domain":           result.Domain,
		"found":            result.DMARC.Found,
		"record":           result.DMARC.Record,
		"policy":           string(result.DMARC.Policy),
		"subdomain_policy": string(result.DMARC.SubdomainPolicy),
		"pct":              result.DMARC.Pct,
		"is_enforced":      result.DMARC.IsEnforced(),
	}
	if result.DMARC.Error != nil {
		dmarcOutput["error"] = result.DMARC.Error.Error()
	}
	findings = append(findings, adapter.RawFinding{
		ToolName:   string(adapter.AdapterIDEmail),
		ToolOutput: dmarcOutput,
	})

	return findings
}
