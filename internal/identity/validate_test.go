package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/goweft/burling/internal/report"
)

// fixedNow returns a deterministic "current time" used across tests.
// All time-bearing fixtures are expressed relative to this value.
func fixedNow() time.Time {
	return time.Date(2026, 4, 16, 12, 0, 0, 0, time.UTC)
}

// mintDoc builds a valid, signed identity document suitable for use as
// a baseline in table-driven tests. Each caller gets a fresh keypair.
func mintDoc(t *testing.T, id string) (raw []byte, priv ed25519.PrivateKey, pub ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := fixedNow()
	tree := map[string]any{
		"aip": "1.0",
		"id":  id,
		"public_keys": []any{
			map[string]any{
				"kid":         "k1",
				"alg":         "ed25519",
				"key":         base64.RawURLEncoding.EncodeToString(pub),
				"valid_from":  now.Add(-24 * time.Hour).Format(time.RFC3339),
				"valid_until": now.Add(24 * time.Hour).Format(time.RFC3339),
			},
		},
	}
	sig, err := signTree(tree, priv)
	if err != nil {
		t.Fatalf("sign tree: %v", err)
	}
	tree["document_signature"] = sig
	raw, err = json.Marshal(tree)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw, priv, pub
}

// signTree canonicalizes tree (with any existing document_signature
// removed) and returns the base64url-encoded Ed25519 signature.
func signTree(tree map[string]any, priv ed25519.PrivateKey) (string, error) {
	stripped := make(map[string]any, len(tree))
	for k, v := range tree {
		if k == "document_signature" {
			continue
		}
		stripped[k] = v
	}
	raw, err := json.Marshal(stripped)
	if err != nil {
		return "", err
	}
	canonical, err := Canonicalize(raw)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, canonical)
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

func reparse(t *testing.T, raw []byte) *Document {
	t.Helper()
	d, err := ParseDocument(raw)
	if err != nil {
		t.Fatalf("ParseDocument: %v", err)
	}
	return d
}

// mutateRaw mutates the parsed tree, re-marshals, and returns fresh
// bytes WITHOUT re-signing. For tests that want to detect tampered
// bodies or corrupted signatures.
func mutateRaw(t *testing.T, raw []byte, fn func(tree map[string]any)) []byte {
	t.Helper()
	var tree map[string]any
	if err := json.Unmarshal(raw, &tree); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	fn(tree)
	out, err := json.Marshal(tree)
	if err != nil {
		t.Fatalf("remarshal: %v", err)
	}
	return out
}

// resign mutates the tree and re-signs it with priv.
func resign(t *testing.T, raw []byte, priv ed25519.PrivateKey, fn func(tree map[string]any)) []byte {
	t.Helper()
	var tree map[string]any
	if err := json.Unmarshal(raw, &tree); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	delete(tree, "document_signature")
	fn(tree)
	sig, err := signTree(tree, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	tree["document_signature"] = sig
	out, err := json.Marshal(tree)
	if err != nil {
		t.Fatalf("remarshal: %v", err)
	}
	return out
}

func hasFinding(r *report.Report, checkID string, sev report.Severity) bool {
	for _, f := range r.Findings {
		if f.CheckID == checkID && f.Severity == sev {
			return true
		}
	}
	return false
}

func TestValidate_AllGreen(t *testing.T) {
	raw, _, _ := mintDoc(t, "aip:web:example.com/agent-alice")
	doc := reparse(t, raw)

	r := Validate(context.Background(), doc, Options{Now: fixedNow})

	for _, f := range r.Findings {
		if f.Severity == report.SeverityError {
			t.Errorf("unexpected ERROR finding: %+v", f)
		}
		if f.Severity == report.SeverityWarning {
			t.Errorf("unexpected WARNING finding on clean document: %+v", f)
		}
	}
	if !hasFinding(r, CheckID08, report.SeverityInfo) {
		t.Errorf("expected ID-08 INFO (no resolver); findings=%+v", r.Findings)
	}
}

func TestValidate_ID01_WrongVersion(t *testing.T) {
	raw, priv, _ := mintDoc(t, "aip:web:example.com/a")
	raw = resign(t, raw, priv, func(tree map[string]any) {
		tree["aip"] = "0.9"
	})
	doc := reparse(t, raw)
	r := Validate(context.Background(), doc, Options{Now: fixedNow})
	if !hasFinding(r, CheckID01, report.SeverityError) {
		t.Errorf("expected ID-01 ERROR; got %+v", r.Findings)
	}
}

func TestValidate_ID02_MalformedID(t *testing.T) {
	cases := []string{
		"",
		"example.com",
		"aip:web:",
		"aip:key:rsa:abc",
		"urn:ietf:params:aip:web:example.com",
	}
	for _, id := range cases {
		t.Run(id, func(t *testing.T) {
			raw, priv, _ := mintDoc(t, "aip:web:example.com/a")
			raw = resign(t, raw, priv, func(tree map[string]any) {
				tree["id"] = id
			})
			doc := reparse(t, raw)
			r := Validate(context.Background(), doc, Options{Now: fixedNow})
			if !hasFinding(r, CheckID02, report.SeverityError) {
				t.Errorf("expected ID-02 ERROR for id=%q; got %+v", id, r.Findings)
			}
		})
	}
}

func TestValidate_ID02_Accepts_KeyForm(t *testing.T) {
	raw, priv, pub := mintDoc(t, "aip:web:example.com/a")
	keyID := "aip:key:ed25519:" + base64.RawURLEncoding.EncodeToString(pub)
	raw = resign(t, raw, priv, func(tree map[string]any) {
		tree["id"] = keyID
	})
	doc := reparse(t, raw)
	r := Validate(context.Background(), doc, Options{Now: fixedNow})
	if hasFinding(r, CheckID02, report.SeverityError) {
		t.Errorf("ID-02 should accept key-form ID; got %+v", r.Findings)
	}
}

func TestValidate_ID03_NoKeys(t *testing.T) {
	raw, priv, _ := mintDoc(t, "aip:web:example.com/a")
	raw = resign(t, raw, priv, func(tree map[string]any) {
		tree["public_keys"] = []any{}
	})
	doc := reparse(t, raw)
	r := Validate(context.Background(), doc, Options{Now: fixedNow})
	if !hasFinding(r, CheckID03, report.SeverityError) {
		t.Errorf("expected ID-03 ERROR; got %+v", r.Findings)
	}
}

func TestValidate_ID04_MissingValidity(t *testing.T) {
	raw, priv, pub := mintDoc(t, "aip:web:example.com/a")
	raw = resign(t, raw, priv, func(tree map[string]any) {
		tree["public_keys"] = []any{
			map[string]any{
				"kid": "k1",
				"alg": "ed25519",
				"key": base64.RawURLEncoding.EncodeToString(pub),
			},
		}
	})
	doc := reparse(t, raw)
	r := Validate(context.Background(), doc, Options{Now: fixedNow})
	if !hasFinding(r, CheckID04, report.SeverityError) {
		t.Errorf("expected ID-04 ERROR; got %+v", r.Findings)
	}
}

func TestValidate_ID05_NoCurrentlyValidKey(t *testing.T) {
	raw, priv, pub := mintDoc(t, "aip:web:example.com/a")
	raw = resign(t, raw, priv, func(tree map[string]any) {
		tree["public_keys"] = []any{
			map[string]any{
				"kid":         "k1",
				"alg":         "ed25519",
				"key":         base64.RawURLEncoding.EncodeToString(pub),
				"valid_from":  fixedNow().Add(-72 * time.Hour).Format(time.RFC3339),
				"valid_until": fixedNow().Add(-24 * time.Hour).Format(time.RFC3339),
			},
		}
	})
	doc := reparse(t, raw)
	r := Validate(context.Background(), doc, Options{Now: fixedNow})
	if !hasFinding(r, CheckID05, report.SeverityError) {
		t.Errorf("expected ID-05 ERROR; got %+v", r.Findings)
	}
}

func TestValidate_ID06_CorruptedSignature(t *testing.T) {
	raw, _, _ := mintDoc(t, "aip:web:example.com/a")
	raw = mutateRaw(t, raw, func(tree map[string]any) {
		sig, _ := tree["document_signature"].(string)
		if sig == "" {
			t.Fatal("no signature to corrupt")
		}
		b, _ := base64.RawURLEncoding.DecodeString(sig)
		b[0] ^= 0xFF
		tree["document_signature"] = base64.RawURLEncoding.EncodeToString(b)
	})
	doc := reparse(t, raw)
	r := Validate(context.Background(), doc, Options{Now: fixedNow})
	if !hasFinding(r, CheckID06, report.SeverityError) {
		t.Errorf("expected ID-06 ERROR; got %+v", r.Findings)
	}
}

func TestValidate_ID06_TamperedBody(t *testing.T) {
	raw, _, _ := mintDoc(t, "aip:web:example.com/a")
	raw = mutateRaw(t, raw, func(tree map[string]any) {
		tree["id"] = "aip:web:evil.com/a"
	})
	doc := reparse(t, raw)
	r := Validate(context.Background(), doc, Options{Now: fixedNow})
	if !hasFinding(r, CheckID06, report.SeverityError) {
		t.Errorf("expected ID-06 ERROR for tampered body; got %+v", r.Findings)
	}
}

func TestValidate_ID07_Expired(t *testing.T) {
	raw, priv, _ := mintDoc(t, "aip:web:example.com/a")
	raw = resign(t, raw, priv, func(tree map[string]any) {
		tree["expires"] = fixedNow().Add(-1 * time.Hour).Format(time.RFC3339)
	})
	doc := reparse(t, raw)
	r := Validate(context.Background(), doc, Options{Now: fixedNow})
	if !hasFinding(r, CheckID07, report.SeverityWarning) {
		t.Errorf("expected ID-07 WARNING; got %+v", r.Findings)
	}
}

func TestValidate_ID08_NoResolver_EmitsInfo(t *testing.T) {
	raw, _, _ := mintDoc(t, "aip:web:example.com/a")
	doc := reparse(t, raw)
	r := Validate(context.Background(), doc, Options{Now: fixedNow, Resolver: nil})
	if !hasFinding(r, CheckID08, report.SeverityInfo) {
		t.Errorf("expected ID-08 INFO when resolver nil; got %+v", r.Findings)
	}
}

func TestValidate_ID08_WithResolver_Matches(t *testing.T) {
	raw, _, _ := mintDoc(t, "aip:web:example.com/a")
	doc := reparse(t, raw)
	resolver := NewMapResolver(doc)
	r := Validate(context.Background(), doc, Options{Now: fixedNow, Resolver: resolver})
	if hasFinding(r, CheckID08, report.SeverityError) {
		t.Errorf("ID-08 should pass with matching resolver; got %+v", r.Findings)
	}
}

func TestValidate_ID08_WithResolver_NotFound(t *testing.T) {
	raw, _, _ := mintDoc(t, "aip:web:example.com/a")
	doc := reparse(t, raw)
	resolver := NewMapResolver()
	r := Validate(context.Background(), doc, Options{Now: fixedNow, Resolver: resolver})
	if !hasFinding(r, CheckID08, report.SeverityError) {
		t.Errorf("expected ID-08 ERROR when resolver cannot find id; got %+v", r.Findings)
	}
}

func TestValidate_ID08_KeyForm_Skipped(t *testing.T) {
	raw, priv, pub := mintDoc(t, "aip:web:example.com/a")
	keyID := "aip:key:ed25519:" + base64.RawURLEncoding.EncodeToString(pub)
	raw = resign(t, raw, priv, func(tree map[string]any) {
		tree["id"] = keyID
	})
	doc := reparse(t, raw)
	r := Validate(context.Background(), doc, Options{Now: fixedNow, Resolver: nil})
	for _, f := range r.Findings {
		if f.CheckID == CheckID08 {
			t.Errorf("ID-08 should be silent for key-form IDs; got %+v", f)
		}
	}
}

func TestValidate_ID09_GapInRotation(t *testing.T) {
	raw, priv, pub := mintDoc(t, "aip:web:example.com/a")
	raw = resign(t, raw, priv, func(tree map[string]any) {
		tree["public_keys"] = []any{
			map[string]any{
				"kid":         "k1",
				"alg":         "ed25519",
				"key":         base64.RawURLEncoding.EncodeToString(pub),
				"valid_from":  fixedNow().Add(-48 * time.Hour).Format(time.RFC3339),
				"valid_until": fixedNow().Add(-24 * time.Hour).Format(time.RFC3339),
			},
			map[string]any{
				"kid":         "k2",
				"alg":         "ed25519",
				"key":         base64.RawURLEncoding.EncodeToString(pub),
				"valid_from":  fixedNow().Add(1 * time.Hour).Format(time.RFC3339),
				"valid_until": fixedNow().Add(48 * time.Hour).Format(time.RFC3339),
			},
		}
	})
	doc := reparse(t, raw)
	r := Validate(context.Background(), doc, Options{Now: fixedNow})
	if !hasFinding(r, CheckID09, report.SeverityWarning) {
		t.Errorf("expected ID-09 WARNING for gap; got %+v", r.Findings)
	}
}

func TestValidate_ID09_OverlappingRotation_Clean(t *testing.T) {
	raw, priv, pub := mintDoc(t, "aip:web:example.com/a")
	raw = resign(t, raw, priv, func(tree map[string]any) {
		tree["public_keys"] = []any{
			map[string]any{
				"kid":         "k1",
				"alg":         "ed25519",
				"key":         base64.RawURLEncoding.EncodeToString(pub),
				"valid_from":  fixedNow().Add(-48 * time.Hour).Format(time.RFC3339),
				"valid_until": fixedNow().Add(1 * time.Hour).Format(time.RFC3339),
			},
			map[string]any{
				"kid":         "k2",
				"alg":         "ed25519",
				"key":         base64.RawURLEncoding.EncodeToString(pub),
				"valid_from":  fixedNow().Add(-1 * time.Hour).Format(time.RFC3339),
				"valid_until": fixedNow().Add(48 * time.Hour).Format(time.RFC3339),
			},
		}
	})
	doc := reparse(t, raw)
	r := Validate(context.Background(), doc, Options{Now: fixedNow})
	if hasFinding(r, CheckID09, report.SeverityWarning) {
		t.Errorf("ID-09 should not warn on overlapping rotation; got %+v", r.Findings)
	}
}

// --- JCS unit tests ---

func TestCanonicalize_ObjectKeyOrdering(t *testing.T) {
	got, err := Canonicalize([]byte(`{"b":1,"a":2,"c":3}`))
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if string(got) != `{"a":2,"b":1,"c":3}` {
		t.Errorf("got %q", string(got))
	}
}

func TestCanonicalize_NumberIntegerPath(t *testing.T) {
	got, err := Canonicalize([]byte(`{"n":42}`))
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if string(got) != `{"n":42}` {
		t.Errorf("got %q", string(got))
	}
}

func TestCanonicalize_StringEscaping(t *testing.T) {
	got, err := Canonicalize([]byte(`{"k":"line1\nline2\ttab\"quote"}`))
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	want := `{"k":"line1\nline2\ttab\"quote"}`
	if string(got) != want {
		t.Errorf("got %q, want %q", string(got), want)
	}
}

func TestCanonicalize_NestedArray(t *testing.T) {
	got, err := Canonicalize([]byte(`{"z":[3,2,1],"a":{"y":1,"x":2}}`))
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	want := `{"a":{"x":2,"y":1},"z":[3,2,1]}`
	if string(got) != want {
		t.Errorf("got %q, want %q", string(got), want)
	}
}

func TestJCS_Ed25519_RoundTrip(t *testing.T) {
	raw, _, _ := mintDoc(t, "aip:web:example.com/round-trip")
	doc := reparse(t, raw)
	r := Validate(context.Background(), doc, Options{Now: fixedNow})
	for _, f := range r.Findings {
		if f.CheckID == CheckID06 && f.Severity == report.SeverityError {
			t.Errorf("ID-06 should verify on freshly minted doc: %+v", f)
		}
	}
}
