package identity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/goweft/burling/internal/report"
)

// Check IDs from docs/conformance-matrix.md §1.
const (
	CheckID01 = "ID-01"
	CheckID02 = "ID-02"
	CheckID03 = "ID-03"
	CheckID04 = "ID-04"
	CheckID05 = "ID-05"
	CheckID06 = "ID-06"
	CheckID07 = "ID-07"
	CheckID08 = "ID-08"
	CheckID09 = "ID-09"
)

// specRef is the AIP §2.3 reference shared by all identity checks.
const specRef = "§2.3"

var (
	webIDPattern = regexp.MustCompile(`^aip:web:[A-Za-z0-9.\-]+(?:/[A-Za-z0-9._\-/]*)?$`)
	keyIDPattern = regexp.MustCompile(`^aip:key:ed25519:[A-Za-z0-9_\-]+$`)
)

// Options configures Validate.
type Options struct {
	// Now returns the "current time" used for validity-window checks.
	// If nil, time.Now is used. Tests pass a fixed time to make
	// ID-05/ID-07/ID-09 deterministic.
	Now func() time.Time

	// Resolver is used for ID-08. If nil, ID-08 emits an INFO finding
	// rather than an ERROR; the caller has explicitly opted out of
	// resolution.
	Resolver Resolver
}

// Validate runs all nine identity checks against doc and returns the
// accumulated report. Findings are appended in check-ID order so the
// report reads top-to-bottom as the matrix does.
//
// doc must have been produced by ParseDocument (or have Raw populated
// equivalently); ID-06 requires the original bytes for canonicalization.
func Validate(ctx context.Context, doc *Document, opts Options) *report.Report {
	r := &report.Report{}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if doc == nil {
		r.Findings = append(r.Findings, report.Finding{
			CheckID:  CheckID01,
			SpecRef:  specRef,
			Severity: report.SeverityError,
			Message:  "identity document is nil",
		})
		return r
	}
	now := opts.Now()

	checkID01(r, doc)
	checkID02(r, doc)
	checkID03(r, doc)
	checkID04(r, doc)
	checkID05(r, doc, now)
	checkID06(r, doc)
	checkID07(r, doc, now)
	checkID08(ctx, r, doc, opts.Resolver)
	checkID09(r, doc)

	return r
}

// add is a small convenience to keep every finding consistent on
// SpecRef and cut the boilerplate in each check.
func add(r *report.Report, checkID string, sev report.Severity, msg string, ctx map[string]any) {
	r.Findings = append(r.Findings, report.Finding{
		CheckID:  checkID,
		SpecRef:  specRef,
		Severity: sev,
		Message:  msg,
		Context:  ctx,
	})
}

// ID-01: aip field equals "1.0" (ERROR)
func checkID01(r *report.Report, d *Document) {
	if d.AIP == "1.0" {
		return
	}
	add(r, CheckID01, report.SeverityError,
		fmt.Sprintf("expected aip field to equal %q, got %q", "1.0", d.AIP),
		map[string]any{"field": "aip", "actual": d.AIP})
}

// ID-02: id is a valid AIP identifier (ERROR)
func checkID02(r *report.Report, d *Document) {
	if webIDPattern.MatchString(d.ID) || keyIDPattern.MatchString(d.ID) {
		return
	}
	add(r, CheckID02, report.SeverityError,
		fmt.Sprintf("id %q is not a valid aip:web: or aip:key:ed25519: identifier", d.ID),
		map[string]any{"field": "id", "actual": d.ID})
}

// ID-03: public_keys is non-empty (ERROR)
func checkID03(r *report.Report, d *Document) {
	if len(d.PublicKeys) > 0 {
		return
	}
	add(r, CheckID03, report.SeverityError, "public_keys array is empty",
		map[string]any{"field": "public_keys"})
}

// ID-04: each key has valid_from and valid_until (ERROR)
func checkID04(r *report.Report, d *Document) {
	for i, k := range d.PublicKeys {
		if k.ValidFrom.IsZero() {
			add(r, CheckID04, report.SeverityError,
				"missing or zero-valued valid_from",
				map[string]any{"field": "public_keys.valid_from", "index": i, "kid": k.KID})
		}
		if k.ValidUntil.IsZero() {
			add(r, CheckID04, report.SeverityError,
				"missing or zero-valued valid_until",
				map[string]any{"field": "public_keys.valid_until", "index": i, "kid": k.KID})
		}
		if !k.ValidFrom.IsZero() && !k.ValidUntil.IsZero() && k.ValidUntil.Before(k.ValidFrom) {
			add(r, CheckID04, report.SeverityError,
				fmt.Sprintf("valid_until (%s) precedes valid_from (%s)",
					k.ValidUntil.Format(time.RFC3339), k.ValidFrom.Format(time.RFC3339)),
				map[string]any{"index": i, "kid": k.KID})
		}
	}
}

// ID-05: at least one key is currently valid (ERROR)
func checkID05(r *report.Report, d *Document, now time.Time) {
	if len(d.PublicKeys) == 0 {
		return // ID-03 already reported
	}
	for _, k := range d.PublicKeys {
		if k.IsValidAt(now) {
			return
		}
	}
	add(r, CheckID05, report.SeverityError,
		fmt.Sprintf("no public key is currently valid at %s", now.Format(time.RFC3339)),
		map[string]any{"now": now.Format(time.RFC3339), "key_count": len(d.PublicKeys)})
}

// ID-06: document_signature verifies against the signing key (ERROR)
//
// Procedure:
//  1. Remove document_signature field from the JSON.
//  2. JCS-canonicalize the remainder.
//  3. Ed25519.Verify(signing_key, canonical, signature).
//
// Signing key is identified by document_signing_kid if present, else
// every Ed25519 key is tried (spec is light here; a single failure
// mode is reported if none verify).
func checkID06(r *report.Report, d *Document) {
	if len(d.Raw) == 0 {
		add(r, CheckID06, report.SeverityError,
			"cannot verify signature: raw document bytes not available",
			map[string]any{"hint": "use ParseDocument to populate Document.Raw"})
		return
	}
	if d.DocumentSignature == "" {
		add(r, CheckID06, report.SeverityError,
			"document_signature is empty",
			map[string]any{"field": "document_signature"})
		return
	}
	sig, err := decodeB64URL(d.DocumentSignature)
	if err != nil {
		add(r, CheckID06, report.SeverityError,
			fmt.Sprintf("document_signature is not valid base64url: %v", err),
			map[string]any{"field": "document_signature"})
		return
	}

	var tree map[string]any
	if err := json.Unmarshal(d.Raw, &tree); err != nil {
		add(r, CheckID06, report.SeverityError,
			fmt.Sprintf("cannot re-parse raw document for signature verification: %v", err),
			nil)
		return
	}
	delete(tree, "document_signature")
	stripped, err := json.Marshal(tree)
	if err != nil {
		add(r, CheckID06, report.SeverityError,
			fmt.Sprintf("re-marshal for canonicalization failed: %v", err),
			nil)
		return
	}
	canonical, err := Canonicalize(stripped)
	if err != nil {
		add(r, CheckID06, report.SeverityError,
			fmt.Sprintf("canonicalize: %v", err), nil)
		return
	}

	candidates := signingKeyCandidates(d)
	if len(candidates) == 0 {
		add(r, CheckID06, report.SeverityError,
			"no ed25519 public key available to verify document_signature", nil)
		return
	}
	for _, k := range candidates {
		if len(k.Key) != ed25519.PublicKeySize {
			continue
		}
		if ed25519.Verify(k.Key, canonical, sig) {
			return
		}
	}
	add(r, CheckID06, report.SeverityError,
		"document_signature did not verify against any listed ed25519 public key",
		map[string]any{"candidate_count": len(candidates)})
}

// signingKeyCandidates returns the ordered list of keys to try for
// document signature verification. If document_signing_kid is set,
// only that key is considered.
func signingKeyCandidates(d *Document) []PublicKey {
	if d.DocumentSigningKID != "" {
		for _, k := range d.PublicKeys {
			if k.KID == d.DocumentSigningKID && strings.EqualFold(k.Alg, "ed25519") {
				return []PublicKey{k}
			}
		}
		return nil
	}
	out := make([]PublicKey, 0, len(d.PublicKeys))
	for _, k := range d.PublicKeys {
		if strings.EqualFold(k.Alg, "ed25519") {
			out = append(out, k)
		}
	}
	return out
}

// ID-07: expires timestamp is in the future (WARNING)
func checkID07(r *report.Report, d *Document, now time.Time) {
	if d.Expires == nil || d.Expires.After(now) {
		return
	}
	add(r, CheckID07, report.SeverityWarning,
		fmt.Sprintf("document expired at %s (now %s)",
			d.Expires.Format(time.RFC3339), now.Format(time.RFC3339)),
		map[string]any{
			"expires": d.Expires.Format(time.RFC3339),
			"now":     now.Format(time.RFC3339),
		})
}

// ID-08: DNS-based ID resolves at well-known URL (ERROR)
//
// Key-form IDs are self-describing and skip HTTP resolution. A nil
// Resolver emits INFO — explicit opt-out beats silent skip.
func checkID08(ctx context.Context, r *report.Report, d *Document, resolver Resolver) {
	if keyIDPattern.MatchString(d.ID) {
		return
	}
	if !webIDPattern.MatchString(d.ID) {
		return // ID-02 already flagged
	}
	if resolver == nil {
		add(r, CheckID08, report.SeverityInfo,
			"ID-08 skipped: no resolver configured",
			map[string]any{"hint": "pass identity.Options.Resolver to verify well-known URL"})
		return
	}
	resolved, err := resolver.Resolve(ctx, d.ID)
	if err != nil {
		add(r, CheckID08, report.SeverityError,
			fmt.Sprintf("failed to resolve %s: %v", d.ID, err),
			map[string]any{"id": d.ID})
		return
	}
	if resolved.ID != d.ID {
		add(r, CheckID08, report.SeverityError,
			fmt.Sprintf("resolved document id %q does not match requested id %q",
				resolved.ID, d.ID),
			map[string]any{"requested": d.ID, "resolved": resolved.ID})
		return
	}
	// Compare canonical forms so whitespace/field-order differences
	// between resolved bytes and document-under-validation bytes do
	// not false-positive.
	canonA, errA := Canonicalize(d.Raw)
	canonB, errB := Canonicalize(resolved.Raw)
	if errA != nil || errB != nil {
		add(r, CheckID08, report.SeverityWarning,
			"resolved document could not be canonicalized for comparison", nil)
		return
	}
	if !bytes.Equal(canonA, canonB) {
		add(r, CheckID08, report.SeverityError,
			"resolved document at well-known URL does not match document under validation",
			map[string]any{"id": d.ID})
	}
}

// ID-09: key validity windows overlap during rotation (WARNING)
//
// Gap detection: walk sorted validity intervals from earliest start.
// Any interval whose start lies after the running max end is a gap.
func checkID09(r *report.Report, d *Document) {
	if len(d.PublicKeys) < 2 {
		return
	}
	type interval struct{ from, until time.Time }
	ivs := make([]interval, 0, len(d.PublicKeys))
	for _, k := range d.PublicKeys {
		if k.ValidFrom.IsZero() || k.ValidUntil.IsZero() {
			continue // ID-04 already reported
		}
		ivs = append(ivs, interval{k.ValidFrom, k.ValidUntil})
	}
	if len(ivs) < 2 {
		return
	}
	// Insertion sort — tiny N.
	for i := 1; i < len(ivs); i++ {
		for j := i; j > 0 && ivs[j].from.Before(ivs[j-1].from); j-- {
			ivs[j], ivs[j-1] = ivs[j-1], ivs[j]
		}
	}
	cursor := ivs[0].until
	for i := 1; i < len(ivs); i++ {
		if ivs[i].from.After(cursor) {
			add(r, CheckID09, report.SeverityWarning,
				fmt.Sprintf("key validity gap between %s and %s — no key is valid in this window",
					cursor.Format(time.RFC3339), ivs[i].from.Format(time.RFC3339)),
				map[string]any{
					"gap_start": cursor.Format(time.RFC3339),
					"gap_end":   ivs[i].from.Format(time.RFC3339),
				})
			return
		}
		if ivs[i].until.After(cursor) {
			cursor = ivs[i].until
		}
	}
}

// decodeB64URL accepts either raw (unpadded) or standard base64url.
func decodeB64URL(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}
