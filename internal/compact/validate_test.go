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

// fixedNow returns the deterministic "current time" used across tests.
func fixedNow() time.Time {
	return time.Date(2026, 4, 16, 12, 0, 0, 0, time.UTC)
}

// mintToken builds a valid compact IBCT plus the issuer identity
// document that would sign it. Each call generates a fresh Ed25519
// keypair. The returned resolver is ready to satisfy CM-03/04.
//
// mutateHeader and mutatePayload let a test tweak the token before
// signing. Pass nil for no mutation.
func mintToken(
	t *testing.T,
	mutateHeader func(map[string]any),
	mutatePayload func(map[string]any),
) (raw string, resolver *identity.MapResolver, issDoc *identity.Document) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	now := fixedNow()
	iss := "aip:web:example.com/issuer-alpha"

	// Build the issuer's identity document first — we need it to hand
	// back via a MapResolver so CM-03 can look up the kid.
	idRaw, _ := mintIdentityDoc(t, iss, "k1", pub, priv)
	issDoc, err = identity.ParseDocument(idRaw)
	if err != nil {
		t.Fatalf("parse identity doc: %v", err)
	}
	resolver = identity.NewMapResolver(issDoc)

	header := map[string]any{
		"alg": "EdDSA",
		"typ": "aip-ibct+jwt",
		"kid": "k1",
	}
	if mutateHeader != nil {
		mutateHeader(header)
	}

	payload := map[string]any{
		"iss":        iss,
		"sub":        "aip:web:example.com/agent-bob",
		"aud":        []string{"aip:web:example.com/mcp-server"},
		"exp":        now.Add(30 * time.Minute).Unix(),
		"nbf":        now.Add(-1 * time.Minute).Unix(),
		"jti":        "01HZ5N8Q3R4TV6W7X8Y9Z0ABCD", // valid ULID shape
		"scope":      map[string]any{"tools": []string{"search"}},
		"invocation": map[string]any{"session_id": "sess-1"},
	}
	if mutatePayload != nil {
		mutatePayload(payload)
	}

	hdrJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	plJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	hdrB64 := base64.RawURLEncoding.EncodeToString(hdrJSON)
	plB64 := base64.RawURLEncoding.EncodeToString(plJSON)
	signingInput := hdrB64 + "." + plB64
	sig := ed25519.Sign(priv, []byte(signingInput))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	raw = signingInput + "." + sigB64
	return raw, resolver, issDoc
}

// mintIdentityDoc is a shim over identity-package's own fixture logic,
// inlined here to avoid a test-only export from the identity package.
// Signs with priv so the resulting doc passes identity.Validate too.
func mintIdentityDoc(
	t *testing.T, id, kid string, pub ed25519.PublicKey, priv ed25519.PrivateKey,
) ([]byte, ed25519.PrivateKey) {
	t.Helper()
	now := fixedNow()
	tree := map[string]any{
		"aip": "1.0",
		"id":  id,
		"public_keys": []any{
			map[string]any{
				"kid":         kid,
				"alg":         "ed25519",
				"key":         base64.RawURLEncoding.EncodeToString(pub),
				"valid_from":  now.Add(-24 * time.Hour).Format(time.RFC3339),
				"valid_until": now.Add(24 * time.Hour).Format(time.RFC3339),
			},
		},
	}
	// Sign with the identity package's canonicalizer. Do this by
	// marshaling and re-canonicalizing through identity's Canonicalize.
	stripped, err := json.Marshal(tree)
	if err != nil {
		t.Fatalf("marshal tree: %v", err)
	}
	canonical, err := identity.Canonicalize(stripped)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	sig := ed25519.Sign(priv, canonical)
	tree["document_signature"] = base64.RawURLEncoding.EncodeToString(sig)
	out, err := json.Marshal(tree)
	if err != nil {
		t.Fatalf("marshal signed tree: %v", err)
	}
	return out, priv
}

func parseOK(t *testing.T, raw string) *Token {
	t.Helper()
	tok, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return tok
}

func hasFinding(r *report.Report, checkID string, sev report.Severity) bool {
	for _, f := range r.Findings {
		if f.CheckID == checkID && f.Severity == sev {
			return true
		}
	}
	return false
}

// --- the nine checks ---

func TestValidate_AllGreen(t *testing.T) {
	raw, resolver, _ := mintToken(t, nil, nil)
	tok := parseOK(t, raw)
	r := Validate(context.Background(), tok, Options{Now: fixedNow, Resolver: resolver})

	for _, f := range r.Findings {
		if f.Severity == report.SeverityError {
			t.Errorf("unexpected ERROR: %+v", f)
		}
		if f.Severity == report.SeverityWarning {
			t.Errorf("unexpected WARNING on clean token: %+v", f)
		}
	}
}

func TestValidate_CM01_WrongAlg(t *testing.T) {
	raw, resolver, _ := mintToken(t, func(h map[string]any) { h["alg"] = "RS256" }, nil)
	tok := parseOK(t, raw)
	r := Validate(context.Background(), tok, Options{Now: fixedNow, Resolver: resolver})
	if !hasFinding(r, CheckCM01, report.SeverityError) {
		t.Errorf("expected CM-01 ERROR; got %+v", r.Findings)
	}
}

func TestValidate_CM02_WrongTyp(t *testing.T) {
	raw, resolver, _ := mintToken(t, func(h map[string]any) { h["typ"] = "JWT" }, nil)
	tok := parseOK(t, raw)
	r := Validate(context.Background(), tok, Options{Now: fixedNow, Resolver: resolver})
	if !hasFinding(r, CheckCM02, report.SeverityError) {
		t.Errorf("expected CM-02 ERROR; got %+v", r.Findings)
	}
}

func TestValidate_CM03_UnknownKID(t *testing.T) {
	raw, resolver, _ := mintToken(t, func(h map[string]any) { h["kid"] = "not-k1" }, nil)
	tok := parseOK(t, raw)
	r := Validate(context.Background(), tok, Options{Now: fixedNow, Resolver: resolver})
	if !hasFinding(r, CheckCM03, report.SeverityError) {
		t.Errorf("expected CM-03 ERROR; got %+v", r.Findings)
	}
}

func TestValidate_CM03_IssuerNotFound(t *testing.T) {
	raw, _, _ := mintToken(t, nil, nil)
	tok := parseOK(t, raw)
	// Empty resolver → issuer resolution fails.
	r := Validate(context.Background(), tok, Options{Now: fixedNow, Resolver: identity.NewMapResolver()})
	if !hasFinding(r, CheckCM03, report.SeverityError) {
		t.Errorf("expected CM-03 ERROR when issuer not resolvable; got %+v", r.Findings)
	}
}

func TestValidate_CM03_NoResolver_EmitsInfo(t *testing.T) {
	raw, _, _ := mintToken(t, nil, nil)
	tok := parseOK(t, raw)
	r := Validate(context.Background(), tok, Options{Now: fixedNow, Resolver: nil})
	if !hasFinding(r, CheckCM03, report.SeverityInfo) {
		t.Errorf("expected CM-03 INFO when resolver nil; got %+v", r.Findings)
	}
	if !hasFinding(r, CheckCM04, report.SeverityInfo) {
		t.Errorf("expected CM-04 INFO when resolver nil; got %+v", r.Findings)
	}
}

func TestValidate_CM04_TamperedPayload(t *testing.T) {
	// Build a valid token, then rewrite the payload portion so the
	// signature no longer verifies.
	raw, resolver, _ := mintToken(t, nil, nil)
	parts := strings.Split(raw, ".")
	// Decode, mutate sub, re-encode — deliberately WITHOUT re-signing.
	plJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var plTree map[string]any
	if err := json.Unmarshal(plJSON, &plTree); err != nil {
		t.Fatal(err)
	}
	plTree["sub"] = "aip:web:evil.com/agent-mallory"
	tamperedPl, _ := json.Marshal(plTree)
	parts[1] = base64.RawURLEncoding.EncodeToString(tamperedPl)
	tampered := strings.Join(parts, ".")

	tok := parseOK(t, tampered)
	r := Validate(context.Background(), tok, Options{Now: fixedNow, Resolver: resolver})
	if !hasFinding(r, CheckCM04, report.SeverityError) {
		t.Errorf("expected CM-04 ERROR for tampered payload; got %+v", r.Findings)
	}
}

func TestValidate_CM05_MissingClaim(t *testing.T) {
	cases := []string{"iss", "sub", "aud", "exp", "nbf", "jti", "scope", "invocation"}
	for _, claim := range cases {
		t.Run("missing_"+claim, func(t *testing.T) {
			raw, resolver, _ := mintToken(t, nil, func(p map[string]any) {
				delete(p, claim)
			})
			tok := parseOK(t, raw)
			r := Validate(context.Background(), tok, Options{Now: fixedNow, Resolver: resolver})
			if !hasFinding(r, CheckCM05, report.SeverityError) {
				t.Errorf("expected CM-05 ERROR for missing %q; got %+v", claim, r.Findings)
			}
		})
	}
}

func TestValidate_CM06_Expired(t *testing.T) {
	raw, resolver, _ := mintToken(t, nil, func(p map[string]any) {
		p["exp"] = fixedNow().Add(-1 * time.Hour).Unix()
		p["nbf"] = fixedNow().Add(-2 * time.Hour).Unix()
	})
	tok := parseOK(t, raw)
	r := Validate(context.Background(), tok, Options{Now: fixedNow, Resolver: resolver})
	if !hasFinding(r, CheckCM06, report.SeverityError) {
		t.Errorf("expected CM-06 ERROR; got %+v", r.Findings)
	}
}

func TestValidate_CM07_NotYetValid(t *testing.T) {
	raw, resolver, _ := mintToken(t, nil, func(p map[string]any) {
		p["nbf"] = fixedNow().Add(1 * time.Hour).Unix()
		p["exp"] = fixedNow().Add(2 * time.Hour).Unix()
	})
	tok := parseOK(t, raw)
	r := Validate(context.Background(), tok, Options{Now: fixedNow, Resolver: resolver})
	if !hasFinding(r, CheckCM07, report.SeverityError) {
		t.Errorf("expected CM-07 ERROR; got %+v", r.Findings)
	}
}

func TestValidate_CM08_TTLExceeded_Standard(t *testing.T) {
	raw, resolver, _ := mintToken(t, nil, func(p map[string]any) {
		p["nbf"] = fixedNow().Add(-1 * time.Minute).Unix()
		p["exp"] = fixedNow().Add(2 * time.Hour).Unix() // 2h01m > 1h cap
	})
	tok := parseOK(t, raw)
	r := Validate(context.Background(), tok, Options{Now: fixedNow, Resolver: resolver})
	if !hasFinding(r, CheckCM08, report.SeverityWarning) {
		t.Errorf("expected CM-08 WARNING; got %+v", r.Findings)
	}
}

func TestValidate_CM08_TTLExceeded_Sensitive(t *testing.T) {
	// 30-minute TTL is fine under standard but exceeds sensitive's 15m cap.
	raw, resolver, _ := mintToken(t, nil, nil) // default 30m TTL
	tok := parseOK(t, raw)
	r := Validate(context.Background(), tok, Options{
		Now: fixedNow, Resolver: resolver, Profile: ProfileSensitive,
	})
	if !hasFinding(r, CheckCM08, report.SeverityWarning) {
		t.Errorf("expected CM-08 WARNING under sensitive profile; got %+v", r.Findings)
	}
}

func TestValidate_CM09_ValidUUIDv4(t *testing.T) {
	raw, resolver, _ := mintToken(t, nil, func(p map[string]any) {
		p["jti"] = "550e8400-e29b-41d4-a716-446655440000"
	})
	tok := parseOK(t, raw)
	r := Validate(context.Background(), tok, Options{Now: fixedNow, Resolver: resolver})
	if hasFinding(r, CheckCM09, report.SeverityWarning) {
		t.Errorf("CM-09 should accept UUIDv4; got %+v", r.Findings)
	}
}

func TestValidate_CM09_InvalidJTI(t *testing.T) {
	raw, resolver, _ := mintToken(t, nil, func(p map[string]any) {
		p["jti"] = "not-a-uuid-or-ulid"
	})
	tok := parseOK(t, raw)
	r := Validate(context.Background(), tok, Options{Now: fixedNow, Resolver: resolver})
	if !hasFinding(r, CheckCM09, report.SeverityWarning) {
		t.Errorf("expected CM-09 WARNING; got %+v", r.Findings)
	}
}

// --- Parse-level tests ---

func TestParse_WrongSegmentCount(t *testing.T) {
	_, err := Parse("a.b") // 2 segments
	if err == nil {
		t.Fatal("expected error for 2-segment input")
	}
}

func TestParse_BadBase64Header(t *testing.T) {
	_, err := Parse("!!!.eyJhIjoxfQ.AA")
	if err == nil {
		t.Fatal("expected error for bad base64 header")
	}
}

func TestParse_BadJSONHeader(t *testing.T) {
	badHdr := base64.RawURLEncoding.EncodeToString([]byte("not json"))
	pl := base64.RawURLEncoding.EncodeToString([]byte(`{"a":1}`))
	sig := base64.RawURLEncoding.EncodeToString([]byte("sig"))
	_, err := Parse(badHdr + "." + pl + "." + sig)
	if err == nil {
		t.Fatal("expected error for non-JSON header")
	}
}

func TestSigningInput_MatchesExpected(t *testing.T) {
	raw, _, _ := mintToken(t, nil, nil)
	tok := parseOK(t, raw)
	i := strings.LastIndex(raw, ".")
	expected := raw[:i]
	if string(tok.SigningInput()) != expected {
		t.Errorf("SigningInput mismatch; got %q, want %q", tok.SigningInput(), expected)
	}
}

// --- payloadContains helper (keeps it exercised for coverage) ---

func TestPayloadContains(t *testing.T) {
	raw, _, _ := mintToken(t, nil, nil)
	tok := parseOK(t, raw)
	if !payloadContains(tok.Payload, "iss") {
		t.Error("expected iss in payload")
	}
	if payloadContains(tok.Payload, "not-a-claim") {
		t.Error("unexpected claim presence")
	}
}
