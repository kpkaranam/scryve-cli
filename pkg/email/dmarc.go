package email

import (
	"context"
	"fmt"
	"strings"
)

// ---------------------------------------------------------------------------
// DMARC result types
// ---------------------------------------------------------------------------

// DMARCPolicy describes the DMARC enforcement policy.
type DMARCPolicy string

const (
	// DMARCPolicyNone means p=none — monitor only, no action taken.
	DMARCPolicyNone DMARCPolicy = "none"

	// DMARCPolicyQuarantine means p=quarantine — suspicious messages go to spam.
	DMARCPolicyQuarantine DMARCPolicy = "quarantine"

	// DMARCPolicyReject means p=reject — failing messages are rejected outright.
	DMARCPolicyReject DMARCPolicy = "reject"

	// DMARCPolicyMissing is the zero value when no DMARC record was found.
	DMARCPolicyMissing DMARCPolicy = ""
)

// DMARCResult holds the outcome of a DMARC check for a domain.
type DMARCResult struct {
	// Found is true when a v=DMARC1 TXT record exists at _dmarc.<domain>.
	Found bool

	// Record is the raw DMARC TXT record value.
	Record string

	// Policy is the parsed p= value.
	Policy DMARCPolicy

	// SubdomainPolicy is the parsed sp= value (inherits Policy when absent).
	SubdomainPolicy DMARCPolicy

	// Pct is the percentage of messages subject to the policy (default 100).
	Pct int

	// RUAF is the list of aggregate-report URIs (rua=).
	RUAF []string

	// RUFS is the list of forensic-report URIs (ruf=).
	RUFS []string

	// Error holds any error encountered during lookup or parsing.
	Error error
}

// IsEnforced returns true when the DMARC policy is quarantine or reject.
func (r DMARCResult) IsEnforced() bool {
	return r.Policy == DMARCPolicyQuarantine || r.Policy == DMARCPolicyReject
}

// ---------------------------------------------------------------------------
// CheckDMARC
// ---------------------------------------------------------------------------

// CheckDMARC queries the TXT record at _dmarc.<domain> and parses the DMARC
// policy.  The resolver is injected so tests can run without real DNS.
func CheckDMARC(ctx context.Context, domain string, resolver Resolver) DMARCResult {
	host := fmt.Sprintf("_dmarc.%s", domain)
	records, err := resolver.LookupTXT(ctx, host)
	if err != nil {
		return DMARCResult{Error: fmt.Errorf("dmarc: lookup %q: %w", host, err)}
	}

	record := findDMARCRecord(records)
	if record == "" {
		return DMARCResult{Found: false, Policy: DMARCPolicyMissing}
	}

	result := parseDMARCRecord(record)
	result.Found = true
	result.Record = record
	return result
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// findDMARCRecord returns the first TXT record that begins with "v=DMARC1"
// (case-insensitive).  Returns "" when none is found.
func findDMARCRecord(records []string) string {
	for _, r := range records {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(r)), "v=dmarc1") {
			return r
		}
	}
	return ""
}

// parseDMARCRecord parses the tag-value pairs in a DMARC TXT record and
// returns a populated DMARCResult (without the Found/Record fields).
func parseDMARCRecord(record string) DMARCResult {
	result := DMARCResult{
		Pct: 100, // DMARC default is 100% when pct= is absent.
	}

	fields := strings.Split(record, ";")
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}

		eqIdx := strings.IndexByte(field, '=')
		if eqIdx < 0 {
			continue
		}

		tag := strings.ToLower(strings.TrimSpace(field[:eqIdx]))
		val := strings.TrimSpace(field[eqIdx+1:])

		switch tag {
		case "p":
			result.Policy = parseDMARCPolicyValue(val)
		case "sp":
			result.SubdomainPolicy = parseDMARCPolicyValue(val)
		case "pct":
			if n, err := parseInt(val); err == nil {
				result.Pct = n
			}
		case "rua":
			result.RUAF = splitURIList(val)
		case "ruf":
			result.RUFS = splitURIList(val)
		}
	}

	// Inherit p= as sp= when sp= is not explicitly set.
	if result.SubdomainPolicy == DMARCPolicyMissing {
		result.SubdomainPolicy = result.Policy
	}

	return result
}

// parseDMARCPolicyValue converts a raw p= or sp= value to a DMARCPolicy.
// Unrecognized values map to DMARCPolicyNone (monitor).
func parseDMARCPolicyValue(v string) DMARCPolicy {
	switch strings.ToLower(v) {
	case "none":
		return DMARCPolicyNone
	case "quarantine":
		return DMARCPolicyQuarantine
	case "reject":
		return DMARCPolicyReject
	}
	return DMARCPolicyNone
}

// splitURIList splits a comma-separated list of URI values (rua=, ruf=).
func splitURIList(v string) []string {
	var out []string
	for _, uri := range strings.Split(v, ",") {
		uri = strings.TrimSpace(uri)
		if uri != "" {
			out = append(out, uri)
		}
	}
	return out
}

// parseInt parses a base-10 integer string. Returns an error for non-numeric input.
func parseInt(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}
