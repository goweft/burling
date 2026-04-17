package compact

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/goweft/burling/internal/identity"
	"github.com/goweft/burling/internal/report"
)

// Check IDs from docs/conformance-matrix.md §2.
const (
	CheckCM01 = "CM-01" // alg is EdDSA
	CheckCM02 = "CM-02" // typ is aip-ibct+jwt
	CheckCM03 = "CM-03" // kid references a key in issuer's identity document
	CheckCM04 = "CM-04" // signature verifies
	CheckCM05 = "CM-05" // required claims present
	CheckCM06 = "CM-06" // exp in the future
	CheckCM07 = "CM-07" // nbf in the past
	CheckCM08 = "CM-08" // ttl does not exceed cap
	CheckCM09 = "CM-09" // jti is a valid UUIDv4 or ULID
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

// ttlCap returns the maximum allowed (exp - nbf) for the profile.
func (p Profile) ttlCap() time.Duration {
	if p == ProfileSensitive {
		return 15 * time.Minute
	}
	return 1 * time.Hour
}

// Options configures Validate.
type Options struct {
	// Now returns the "current time" used for exp/nbf checks.
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

// requiredClaims per §3.1. Iteration order doesn't matter for
// correctness; tests compare against the set.
var requiredClaims = []string{
	"iss", "sub", "aud", "exp", "nbf", "jti", "scope", "invocation",
}

// uuidV4Pattern matches the canonical UUIDv4 form. The 13th hex digit
// must be 4, and the 17th must be one of 8/9/a/b (clock_seq_hi_and_reserved
// variant bits).
var uuidV4Pattern = regexp.MustCompile(
	`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`,
)

// ulidPattern: 26 characters of Crockford base32 (0-9, A-Z minus ILOU).
var ulidPattern = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{26}$`)

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

// CM-02: typ is aip-ibct+jwt (ERROR)
func checkCM02(r *report.Report, tok *Token) {
	if tok.Header.Typ == "aip-ibct+jwt" {
		return
	}
	add(r, CheckCM02, report.SeverityError,
		fmt.Sprintf("expected typ %q, got %q", "aip-ibct+jwt", tok.Header.Typ),
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

// CM-07: nbf is in the past (ERROR)
//
// The boundary case (nbf == now) is treated as "valid right now" per
// the RFC 7519 "not before" reading; only strictly-future nbf fails.
func checkCM07(r *report.Report, tok *Token, now time.Time) {
	if tok.Payload.NotBefore == 0 {
		return // CM-05 covers absence
	}
	nbf := time.Unix(tok.Payload.NotBefore, 0).UTC()
	if !nbf.After(now) {
		return
	}
	add(r, CheckCM07, report.SeverityError,
		fmt.Sprintf("token not yet valid; nbf=%s now=%s", nbf.Format(time.RFC3339), now.Format(time.RFC3339)),
		map[string]any{"nbf": nbf.Format(time.RFC3339), "now": now.Format(time.RFC3339)})
}

// CM-08: exp - nbf does not exceed the profile's TTL cap (WARNING)
func checkCM08(r *report.Report, tok *Token, profile Profile) {
	if tok.Payload.Expiry == 0 || tok.Payload.NotBefore == 0 {
		return // CM-05 covers absence; CM-06/07 cover ordering
	}
	exp := time.Unix(tok.Payload.Expiry, 0).UTC()
	nbf := time.Unix(tok.Payload.NotBefore, 0).UTC()
	ttl := exp.Sub(nbf)
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

// CM-09: jti is a valid UUIDv4 or ULID (WARNING)
func checkCM09(r *report.Report, tok *Token) {
	if tok.Payload.JTI == "" {
		return // CM-05 covers absence
	}
	if uuidV4Pattern.MatchString(tok.Payload.JTI) {
		return
	}
	if ulidPattern.MatchString(tok.Payload.JTI) {
		return
	}
	add(r, CheckCM09, report.SeverityWarning,
		fmt.Sprintf("jti %q is neither a UUIDv4 nor a ULID", tok.Payload.JTI),
		map[string]any{"jti": tok.Payload.JTI})
}

// payloadContains is a small helper used by tests to check whether a
// claim is present in a parsed Payload's Raw map. Exported via test
// file, not generally useful outside it.
func payloadContains(p Payload, claim string) bool {
	_, ok := p.Raw[claim]
	return ok
}

