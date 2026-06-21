package compact

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"strings"
	"time"

	"github.com/goweft/burling/internal/identity"
	"github.com/goweft/burling/internal/report"
)

// Check IDs from docs/conformance-matrix.md §2.
const (
	CheckCM01 = "CM-01" // alg is EdDSA
	CheckCM02 = "CM-02" // typ is aip+jwt
	CheckCM03 = "CM-03" // kid references a key in issuer's identity document
	CheckCM04 = "CM-04" // signature verifies
	CheckCM05 = "CM-05" // required claims present
	CheckCM06 = "CM-06" // exp in the future
	CheckCM07 = "CM-07" // iat in the past
	CheckCM08 = "CM-08" // ttl (exp - iat) does not exceed cap
	CheckCM09 = "CM-09" // budget_usd is non-negative
)

const specRef = "§3.1"

// Profile names per §3.4. Compact mode uses these to determine the
// CM-08 TTL ceiling. The explicit-profile ambiguity is flagged in
// docs/spec-ambiguities.md (ambiguity-03); v0.1 defaults to standard.
type Profile string

const (
	ProfileStandard  Profile = "standard"
	ProfileSensitive Profile = "sensitive"
)

// ttlCap returns the maximum allowed (exp - iat) for the profile.
func (p Profile) ttlCap() time.Duration {
	if p == ProfileSensitive {
		return 15 * time.Minute
	}
	return 1 * time.Hour
}

// Options configures Validate.
type Options struct {
	// Now returns the "current time" used for exp/iat checks.
	Now func() time.Time

	// Resolver is used for CM-03 and CM-04 to fetch the issuer's
	// identity document. If nil, CM-03 and CM-04 emit INFO findings
	// rather than ERROR — consistent with ID-08's nil-resolver policy.
	Resolver identity.Resolver

	// Profile selects the TTL ceiling used by CM-08. Defaults to
	// standard (1h cap). TODO(ambiguity-03): no explicit profile field
	// in the token; burling accepts this as an input until the spec
	// defines a marker.
	Profile Profile
}

// requiredClaims per §3.1: the seven claims a compact IBCT MUST carry.
// Iteration order doesn't matter for correctness; tests compare against
// the set.
var requiredClaims = []string{
	"iss", "sub", "scope", "budget_usd", "max_depth", "iat", "exp",
}

// Validate runs all nine compact-mode checks against tok and returns
// the accumulated report. Checks are dispatched in matrix order.
func Validate(ctx context.Context, tok *Token, opts Options) *report.Report {
	r := &report.Report{}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Profile == "" {
		opts.Profile = ProfileStandard
	}
	if tok == nil {
		r.Findings = append(r.Findings, report.Finding{
			CheckID:  CheckCM01,
			SpecRef:  specRef,
			Severity: report.SeverityError,
			Message:  "token is nil",
		})
		return r
	}
	now := opts.Now()

	// CM-03/04 share a resolution step; doing it once avoids redundant
	// Resolver.Resolve calls and lets CM-04 skip when CM-03 already
	// failed with a clear reason.
	keyFound, resolved := resolveKey(ctx, r, tok, opts.Resolver)

	checkCM01(r, tok)
	checkCM02(r, tok)
	// CM-03 findings were emitted by resolveKey; nothing extra here.
	checkCM04(r, tok, keyFound, resolved, opts.Resolver)
	checkCM05(r, tok)
	checkCM06(r, tok, now)
	checkCM07(r, tok, now)
	checkCM08(r, tok, opts.Profile)
	checkCM09(r, tok)

	return r
}

func add(r *report.Report, checkID string, sev report.Severity, msg string, ctx map[string]any) {
	r.Findings = append(r.Findings, report.Finding{
		CheckID:  checkID,
		SpecRef:  specRef,
		Severity: sev,
		Message:  msg,
		Context:  ctx,
	})
}

// CM-01: alg is EdDSA (ERROR)
func checkCM01(r *report.Report, tok *Token) {
	if tok.Header.Alg == "EdDSA" {
		return
	}
	add(r, CheckCM01, report.SeverityError,
		fmt.Sprintf("expected alg %q, got %q", "EdDSA", tok.Header.Alg),
		map[string]any{"actual": tok.Header.Alg})
}

// CM-02: typ is aip+jwt (ERROR)
func checkCM02(r *report.Report, tok *Token) {
	if tok.Header.Typ == "aip+jwt" {
		return
	}
	add(r, CheckCM02, report.SeverityError,
		fmt.Sprintf("expected typ %q, got %q", "aip+jwt", tok.Header.Typ),
		map[string]any{"actual": tok.Header.Typ})
}

// resolveKey implements CM-03: it fetches the issuer's identity
// document via the Resolver and finds the public key matching the
// token's kid. It returns the key bytes and the resolved document,
// and records CM-03 findings as it goes.
//
// The returned PublicKey has Key already decoded (ParseDocument does
// this), so CM-04 can pass it straight to ed25519.Verify.
func resolveKey(
	ctx context.Context, r *report.Report, tok *Token, resolver identity.Resolver,
) (*identity.PublicKey, *identity.Document) {
	if tok.Payload.Issuer == "" {
		add(r, CheckCM03, report.SeverityError,
			"cannot resolve signing key: iss claim is empty",
			map[string]any{"field": "iss"})
		return nil, nil
	}
	if tok.Header.KID == "" {
		add(r, CheckCM03, report.SeverityError,
			"header kid is empty",
			map[string]any{"field": "kid"})
		return nil, nil
	}
	if resolver == nil {
		add(r, CheckCM03, report.SeverityInfo,
			"CM-03 skipped: no resolver configured",
			map[string]any{"hint": "pass compact.Options.Resolver to verify kid against issuer identity document"})
		return nil, nil
	}
	doc, err := resolver.Resolve(ctx, tok.Payload.Issuer)
	if err != nil {
		add(r, CheckCM03, report.SeverityError,
			fmt.Sprintf("failed to resolve issuer %q: %v", tok.Payload.Issuer, err),
			map[string]any{"iss": tok.Payload.Issuer})
		return nil, nil
	}
	for i := range doc.PublicKeys {
		k := &doc.PublicKeys[i]
		if k.KID != tok.Header.KID {
			continue
		}
		if !strings.EqualFold(k.Alg, "ed25519") {
			add(r, CheckCM03, report.SeverityError,
				fmt.Sprintf("kid %q matches a key with alg %q, want ed25519", k.KID, k.Alg),
				map[string]any{"kid": k.KID, "alg": k.Alg})
			return nil, doc
		}
		return k, doc
	}
	add(r, CheckCM03, report.SeverityError,
		fmt.Sprintf("kid %q not found in issuer %q identity document", tok.Header.KID, tok.Payload.Issuer),
		map[string]any{"kid": tok.Header.KID, "iss": tok.Payload.Issuer})
	return nil, doc
}

// CM-04: signature verifies against resolved public key (ERROR)
//
// If CM-03 could not find a key, CM-04 reports INFO ("could not verify;
// key resolution failed") rather than ERROR — the real failure was
// upstream, double-erroring just adds noise.
func checkCM04(
	r *report.Report, tok *Token, key *identity.PublicKey, _ *identity.Document,
	resolver identity.Resolver,
) {
	if resolver == nil {
		add(r, CheckCM04, report.SeverityInfo,
			"CM-04 skipped: no resolver configured",
			nil)
		return
	}
	if key == nil {
		add(r, CheckCM04, report.SeverityInfo,
			"CM-04 skipped: signing key could not be resolved (see CM-03)",
			nil)
		return
	}
	if len(key.Key) != ed25519.PublicKeySize {
		add(r, CheckCM04, report.SeverityError,
			fmt.Sprintf("resolved key has length %d, want %d", len(key.Key), ed25519.PublicKeySize),
			map[string]any{"kid": key.KID})
		return
	}
	if !ed25519.Verify(key.Key, tok.SigningInput(), tok.SignatureRaw) {
		add(r, CheckCM04, report.SeverityError,
			"signature did not verify against resolved public key",
			map[string]any{"kid": key.KID})
	}
}

// CM-05: required claims present (ERROR)
//
// "Present" means the top-level JSON key exists. A claim set to null
// or to an empty string counts as present for CM-05 — this check is
// purely structural. Value-level checks (non-empty iss, parseable
// exp, etc.) are the other checks' jobs.
func checkCM05(r *report.Report, tok *Token) {
	for _, name := range requiredClaims {
		if _, ok := tok.Payload.Raw[name]; !ok {
			add(r, CheckCM05, report.SeverityError,
				fmt.Sprintf("required claim %q is missing", name),
				map[string]any{"claim": name})
		}
	}
}

// CM-06: exp is in the future (ERROR)
func checkCM06(r *report.Report, tok *Token, now time.Time) {
	if tok.Payload.Expiry == 0 {
		return // CM-05 covers absence
	}
	exp := time.Unix(tok.Payload.Expiry, 0).UTC()
	if exp.After(now) {
		return
	}
	add(r, CheckCM06, report.SeverityError,
		fmt.Sprintf("token expired at %s (now %s)", exp.Format(time.RFC3339), now.Format(time.RFC3339)),
		map[string]any{"exp": exp.Format(time.RFC3339), "now": now.Format(time.RFC3339)})
}

// CM-07: iat is in the past (ERROR)
//
// A token issued in the future is invalid. The boundary case
// (iat == now) is treated as valid right now; only a strictly-future
// iat fails.
func checkCM07(r *report.Report, tok *Token, now time.Time) {
	if tok.Payload.IssuedAt == 0 {
		return // CM-05 covers absence
	}
	iat := time.Unix(tok.Payload.IssuedAt, 0).UTC()
	if !iat.After(now) {
		return
	}
	add(r, CheckCM07, report.SeverityError,
		fmt.Sprintf("token issued in the future; iat=%s now=%s", iat.Format(time.RFC3339), now.Format(time.RFC3339)),
		map[string]any{"iat": iat.Format(time.RFC3339), "now": now.Format(time.RFC3339)})
}

// CM-08: exp - iat does not exceed the profile's TTL cap (WARNING)
func checkCM08(r *report.Report, tok *Token, profile Profile) {
	if tok.Payload.Expiry == 0 || tok.Payload.IssuedAt == 0 {
		return // CM-05 covers absence; CM-06/07 cover ordering
	}
	exp := time.Unix(tok.Payload.Expiry, 0).UTC()
	iat := time.Unix(tok.Payload.IssuedAt, 0).UTC()
	ttl := exp.Sub(iat)
	capDur := profile.ttlCap()
	if ttl <= capDur {
		return
	}
	add(r, CheckCM08, report.SeverityWarning,
		fmt.Sprintf("ttl %s exceeds %s cap of %s", ttl, profile, capDur),
		map[string]any{
			"ttl":     ttl.String(),
			"cap":     capDur.String(),
			"profile": string(profile),
		})
}

// CM-09: budget_usd is non-negative (ERROR)
//
// Per §3.5, the verifier checks that the authorization budget is
// non-negative. A negative ceiling is malformed. Absence is CM-05's
// concern; a present budget of zero is permitted — it authorizes no
// spend, which is a coherent (if restrictive) grant.
func checkCM09(r *report.Report, tok *Token) {
	if tok.Payload.BudgetUSD < 0 {
		add(r, CheckCM09, report.SeverityError,
			fmt.Sprintf("budget_usd is negative: %v", tok.Payload.BudgetUSD),
			map[string]any{"budget_usd": tok.Payload.BudgetUSD})
	}
}

// payloadContains is a small helper used by tests to check whether a
// claim is present in a parsed Payload's Raw map. Exported via test
// file, not generally useful outside it.
func payloadContains(p Payload, claim string) bool {
	_, ok := p.Raw[claim]
	return ok
}
