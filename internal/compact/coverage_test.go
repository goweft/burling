package compact

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/goweft/burling/internal/identity"
	"github.com/goweft/burling/internal/report"
)

// --- Parse branch coverage ---

func TestParse_BadBase64Payload(t *testing.T) {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA"}`))
	_, err := Parse(hdr + ".!!!.AA")
	if err == nil {
		t.Fatal("expected error for bad base64 payload")
	}
}

func TestParse_BadBase64Signature(t *testing.T) {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA"}`))
	pl := base64.RawURLEncoding.EncodeToString([]byte(`{"a":1}`))
	_, err := Parse(hdr + "." + pl + ".!!!")
	if err == nil {
		t.Fatal("expected error for bad base64 signature")
	}
}

func TestParse_BadJSONPayload(t *testing.T) {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA"}`))
	pl := base64.RawURLEncoding.EncodeToString([]byte(`not json`))
	sig := base64.RawURLEncoding.EncodeToString([]byte("s"))
	_, err := Parse(hdr + "." + pl + "." + sig)
	if err == nil {
		t.Fatal("expected error for non-JSON payload")
	}
}

// --- SigningInput defensive branch ---

func TestSigningInput_NoDot(t *testing.T) {
	tok := &Token{Raw: "no-dots-here"}
	if tok.SigningInput() != nil {
		t.Errorf("expected nil for dot-less Raw, got %q", tok.SigningInput())
	}
}

// --- resolveKey branch coverage ---

func TestValidate_CM03_EmptyIssuer(t *testing.T) {
	raw, resolver, _ := mintToken(t, nil, func(p map[string]any) {
		p["iss"] = ""
	})
	tok := parseOK(t, raw)
	r := Validate(context.Background(), tok, Options{Now: fixedNow, Resolver: resolver})
	if !hasFinding(r, CheckCM03, report.SeverityError) {
		t.Errorf("expected CM-03 ERROR for empty iss; got %+v", r.Findings)
	}
}

func TestValidate_CM03_EmptyKID(t *testing.T) {
	raw, resolver, _ := mintToken(t, func(h map[string]any) {
		h["kid"] = ""
	}, nil)
	tok := parseOK(t, raw)
	r := Validate(context.Background(), tok, Options{Now: fixedNow, Resolver: resolver})
	if !hasFinding(r, CheckCM03, report.SeverityError) {
		t.Errorf("expected CM-03 ERROR for empty kid; got %+v", r.Findings)
	}
}

// TestValidate_CM03_KIDFoundButWrongAlg covers the branch where the
// kid resolves to a key listed with an alg other than ed25519.
func TestValidate_CM03_KIDFoundButWrongAlg(t *testing.T) {
	raw, _, issDoc := mintToken(t, nil, nil)
	issDoc.PublicKeys[0].Alg = "rsa"
	resolver := identity.NewMapResolver(issDoc)
	tok := parseOK(t, raw)
	r := Validate(context.Background(), tok, Options{Now: fixedNow, Resolver: resolver})
	if !hasFinding(r, CheckCM03, report.SeverityError) {
		t.Errorf("expected CM-03 ERROR for non-ed25519 alg match; got %+v", r.Findings)
	}
}

// --- checkCM04 branch coverage ---

func TestValidate_CM04_WrongLengthKey(t *testing.T) {
	raw, _, issDoc := mintToken(t, nil, nil)
	issDoc.PublicKeys[0].Key = []byte{0x01, 0x02, 0x03}
	resolver := identity.NewMapResolver(issDoc)
	tok := parseOK(t, raw)
	r := Validate(context.Background(), tok, Options{Now: fixedNow, Resolver: resolver})
	if !hasFinding(r, CheckCM04, report.SeverityError) {
		t.Errorf("expected CM-04 ERROR for malformed key length; got %+v", r.Findings)
	}
}

// --- Validate-level branches ---

func TestValidate_NilToken(t *testing.T) {
	r := Validate(context.Background(), nil, Options{Now: fixedNow})
	if !hasFinding(r, CheckCM01, report.SeverityError) {
		t.Errorf("expected CM-01 ERROR for nil token; got %+v", r.Findings)
	}
}

// TestValidate_DefaultNowAndProfile exercises Now=nil -> time.Now and
// Profile="" -> ProfileStandard. The token must be valid against the
// real wall clock, so it's minted with time.Now()-relative windows
// rather than fixedNow().
func TestValidate_DefaultNowAndProfile(t *testing.T) {
	raw, resolver, _ := mintTokenLive(t, time.Now())
	tok := parseOK(t, raw)
	r := Validate(context.Background(), tok, Options{Resolver: resolver})
	if r.HasErrors() {
		t.Errorf("expected no errors with default options; got %+v", r.Findings)
	}
}

// mintTokenLive builds a compact IBCT whose exp/nbf windows are
// anchored at the given reference time. Used by tests that run
// Validate without a fixed Now.
func mintTokenLive(t *testing.T, ref time.Time) (string, *identity.MapResolver, *identity.Document) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	iss := "aip:web:example.com/issuer-live"
	idTree := map[string]any{
		"aip": "1.0",
		"id":  iss,
		"public_keys": []any{
			map[string]any{
				"kid":         "k1",
				"alg":         "ed25519",
				"key":         base64.RawURLEncoding.EncodeToString(pub),
				"valid_from":  ref.Add(-24 * time.Hour).Format(time.RFC3339),
				"valid_until": ref.Add(24 * time.Hour).Format(time.RFC3339),
			},
		},
	}
	idJSON, err := json.Marshal(idTree)
	if err != nil {
		t.Fatalf("marshal id tree: %v", err)
	}
	canonical, err := identity.Canonicalize(idJSON)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	idTree["document_signature"] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, canonical))
	idRaw, err := json.Marshal(idTree)
	if err != nil {
		t.Fatalf("marshal signed id: %v", err)
	}
	issDoc, err := identity.ParseDocument(idRaw)
	if err != nil {
		t.Fatalf("parse id: %v", err)
	}
	resolver := identity.NewMapResolver(issDoc)

	header := map[string]any{"alg": "EdDSA", "typ": "aip-ibct+jwt", "kid": "k1"}
	payload := map[string]any{
		"iss":        iss,
		"sub":        "aip:web:example.com/agent-live",
		"aud":        []string{"aip:web:example.com/mcp"},
		"exp":        ref.Add(30 * time.Minute).Unix(),
		"nbf":        ref.Add(-1 * time.Minute).Unix(),
		"jti":        "01HZ5N8Q3R4TV6W7X8Y9Z0ABCD",
		"scope":      map[string]any{"tools": []string{"search"}},
		"invocation": map[string]any{"session_id": "sess-live"},
	}
	hdrJSON, _ := json.Marshal(header)
	plJSON, _ := json.Marshal(payload)
	hdrB64 := base64.RawURLEncoding.EncodeToString(hdrJSON)
	plB64 := base64.RawURLEncoding.EncodeToString(plJSON)
	signingInput := hdrB64 + "." + plB64
	sig := ed25519.Sign(priv, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), resolver, issDoc
}

// --- CM-09 UUIDv4 variant bit edge case ---

func TestValidate_CM09_WrongVariantBit(t *testing.T) {
	raw, resolver, _ := mintToken(t, nil, func(p map[string]any) {
		p["jti"] = "550e8400-e29b-41d4-c716-446655440000"
	})
	tok := parseOK(t, raw)
	r := Validate(context.Background(), tok, Options{Now: fixedNow, Resolver: resolver})
	if !hasFinding(r, CheckCM09, report.SeverityWarning) {
		t.Errorf("expected CM-09 WARNING for invalid variant bit; got %+v", r.Findings)
	}
}

// --- CM-06/07 boundary: exact-now ---

func TestValidate_CM07_NBFExactlyNow(t *testing.T) {
	raw, resolver, _ := mintToken(t, nil, func(p map[string]any) {
		p["nbf"] = fixedNow().Unix()
		p["exp"] = fixedNow().Add(30 * time.Minute).Unix()
	})
	tok := parseOK(t, raw)
	r := Validate(context.Background(), tok, Options{Now: fixedNow, Resolver: resolver})
	if hasFinding(r, CheckCM07, report.SeverityError) {
		t.Errorf("CM-07 should allow nbf==now; got %+v", r.Findings)
	}
}

// --- Profile string plumbs through ---

func TestProfile_TTLCap(t *testing.T) {
	if ProfileStandard.ttlCap() != 1*time.Hour {
		t.Error("standard cap wrong")
	}
	if ProfileSensitive.ttlCap() != 15*time.Minute {
		t.Error("sensitive cap wrong")
	}
	if Profile("unknown").ttlCap() != 1*time.Hour {
		t.Error("unknown profile should use standard cap")
	}
}

// Regression guard: the minted issuer id form aip:web:... must look
// like what identity.Validate would accept.
func TestMintToken_IssuerLooksValid(t *testing.T) {
	raw, _, issDoc := mintToken(t, nil, nil)
	if !strings.HasPrefix(issDoc.ID, "aip:web:") {
		t.Errorf("minted issuer id %q doesn't look like aip:web:", issDoc.ID)
	}
	if !strings.Contains(raw, ".") {
		t.Error("minted token has no dots")
	}
}

// TestMintToken_IssuerDocPassesIdentityValidate is a cross-package
// regression guard: the issuer identity document that compact fixtures
// produce must also be valid per identity.Validate. If the two
// packages ever disagree on what a well-formed identity document
// looks like, this test catches it before the silent divergence
// ships.
func TestMintToken_IssuerDocPassesIdentityValidate(t *testing.T) {
	_, _, issDoc := mintToken(t, nil, nil)
	r := identity.Validate(context.Background(), issDoc, identity.Options{
		Now: fixedNow,
		// No Resolver: ID-08 emits INFO for web-form IDs, which is
		// expected and not an error condition.
	})
	if r.HasErrors() {
		t.Errorf("compact-minted issuer doc fails identity.Validate: %+v", r.Findings)
	}
}
