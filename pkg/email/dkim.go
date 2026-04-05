package email

import (
	"context"
	"fmt"
	"strings"
)

// ---------------------------------------------------------------------------
// DKIM result types
// ---------------------------------------------------------------------------

// DKIMSelectorResult holds the result of probing a single DKIM selector.
type DKIMSelectorResult struct {
	// Selector is the DKIM selector name that was probed (e.g. "google", "mail").
	Selector string

	// Found is true when a DKIM TXT record exists at <selector>._domainkey.<domain>.
	Found bool

	// Record is the raw TXT record value when Found is true.
	Record string

	// KeyLength is the RSA key length in bits (2048, 1024, etc.) when
	// determinable from the p= value. 0 means not determined.
	KeyLength int
}

// DKIMResult holds the aggregate outcome of probing common DKIM selectors.
type DKIMResult struct {
	// Selectors is the per-selector results for all probed selectors.
	Selectors []DKIMSelectorResult

	// Found is true when at least one DKIM selector record was discovered.
	Found bool

	// Error holds any fatal error encountered during lookup.
	Error error
}

// commonSelectors is the list of DKIM selectors probed by CheckDKIM.
// These are the nine most frequently used selectors in the wild.
var commonSelectors = []string{
	"default",
	"google",
	"mail",
	"k1",
	"selector1",
	"selector2",
	"dkim",
	"s1",
	"s2",
}

// ---------------------------------------------------------------------------
// CheckDKIM
// ---------------------------------------------------------------------------

// CheckDKIM probes the nine common DKIM selectors for domain and returns the
// aggregate result.  The resolver is injected so tests can run without real DNS.
//
// For each selector the function queries: <selector>._domainkey.<domain>
// If a record is found the p= (public key) length is estimated from the
// base64-encoded key data (approximate, not exact RSA key size).
func CheckDKIM(ctx context.Context, domain string, resolver Resolver) DKIMResult {
	var results []DKIMSelectorResult
	found := false

	for _, sel := range commonSelectors {
		host := fmt.Sprintf("%s._domainkey.%s", sel, domain)
		records, err := resolver.LookupTXT(ctx, host)
		if err != nil {
			// DNS error for this selector — record it but continue.
			results = append(results, DKIMSelectorResult{
				Selector: sel,
				Found:    false,
			})
			continue
		}

		record := findDKIMRecord(records)
		if record == "" {
			results = append(results, DKIMSelectorResult{
				Selector: sel,
				Found:    false,
			})
			continue
		}

		keyLen := estimateKeyLength(record)
		found = true
		results = append(results, DKIMSelectorResult{
			Selector:  sel,
			Found:     true,
			Record:    record,
			KeyLength: keyLen,
		})
	}

	return DKIMResult{
		Selectors: results,
		Found:     found,
	}
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// findDKIMRecord returns the first TXT record that contains "v=DKIM1" or has
// a "p=" field (indicating a DKIM public key record).  Returns "" when none
// is found.
func findDKIMRecord(records []string) string {
	for _, r := range records {
		lower := strings.ToLower(r)
		if strings.Contains(lower, "v=dkim1") || strings.Contains(r, "p=") {
			return r
		}
	}
	return ""
}

// estimateKeyLength attempts to estimate the RSA key length in bits from the
// base64-encoded public key in the p= field of a DKIM TXT record.
//
// RSA key length estimation from base64-encoded DER (PKCS#1 SubjectPublicKeyInfo):
//   - 2048-bit key → ~300–392 base64 chars in the p= field
//   - 1024-bit key → ~100–216 base64 chars
//   - 512-bit key  → fewer chars
//
// This is a heuristic — for an exact value the DER would need to be decoded.
func estimateKeyLength(record string) int {
	pValue := extractDKIMField(record, "p")
	if pValue == "" {
		return 0
	}
	// Remove whitespace that may appear in multi-part TXT records.
	pValue = strings.ReplaceAll(pValue, " ", "")
	pValue = strings.ReplaceAll(pValue, "\t", "")

	l := len(pValue)
	switch {
	case l >= 300:
		return 2048
	case l >= 100:
		return 1024
	case l > 0:
		return 512
	}
	return 0
}

// extractDKIMField returns the value of a named tag (e.g. "p") from a DKIM
// TXT record formatted as "tag=value; tag=value; …".
func extractDKIMField(record, tag string) string {
	// Split on semicolons and scan each field.
	fields := strings.Split(record, ";")
	prefix := tag + "="
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if strings.HasPrefix(f, prefix) {
			return strings.TrimPrefix(f, prefix)
		}
	}
	return ""
}
