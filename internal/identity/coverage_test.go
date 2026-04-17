package identity

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/goweft/burling/internal/report"
)

// --- HTTPResolver + WebIDToURL branch coverage ---

func TestWebIDToURL_Cases(t *testing.T) {
	cases := []struct {
		name    string
		id      string
		want    string
		wantErr bool
	}{
		{"web with path", "aip:web:example.com/agent-alice",
			"https://example.com/.well-known/aip/agent-alice.json", false},
		{"web with nested path", "aip:web:example.com/team/bob",
			"https://example.com/.well-known/aip/team/bob.json", false},
		{"web empty path falls back to root", "aip:web:example.com",
			"https://example.com/.well-known/aip/root.json", false},
		{"not aip:web: prefix", "aip:key:ed25519:abc", "", true},
		{"empty authority after prefix", "aip:web:", "", true},
		{"slash only after prefix (empty domain)", "aip:web:/path", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := WebIDToURL(tc.id)
			if tc.wantErr {
				if err == nil {
					t.Errorf("WebIDToURL(%q) = %q, want error", tc.id, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("WebIDToURL(%q) unexpected error: %v", tc.id, err)
			}
			if got != tc.want {
				t.Errorf("WebIDToURL(%q) = %q, want %q", tc.id, got, tc.want)
			}
		})
	}
}

func TestNewHTTPResolver_Defaults(t *testing.T) {
	h := NewHTTPResolver()
	if h == nil {
		t.Fatal("NewHTTPResolver returned nil")
	}
	if h.Client == nil {
		t.Fatal("NewHTTPResolver client is nil")
	}
	if h.Client.Timeout != 10*time.Second {
		t.Errorf("default timeout = %v, want 10s", h.Client.Timeout)
	}
}

// httpResolverWithRewrittenHost rewrites the resolver's request URLs
// to the test server's URL, while keeping the original path derived
// by WebIDToURL. This lets us drive HTTPResolver end-to-end without
// real DNS.
func httpResolverWithRewrittenHost(t *testing.T, srv *httptest.Server) *HTTPResolver {
	t.Helper()
	base := strings.TrimPrefix(srv.URL, "http://")
	return &HTTPResolver{
		Client: &http.Client{
			Timeout: 2 * time.Second,
			Transport: rewriteTransport{
				target: base,
				// wrap the default transport for the actual round-trip
				next: http.DefaultTransport,
			},
		},
	}
}

// rewriteTransport forces all requests to use http://<target>,
// preserving path/query. Used only by tests.
type rewriteTransport struct {
	target string
	next   http.RoundTripper
}

func (r rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "http"
	req.URL.Host = r.target
	req.Host = r.target
	return r.next.RoundTrip(req)
}

func TestHTTPResolver_Resolve_OK(t *testing.T) {
	raw, _, _ := mintDoc(t, "aip:web:example.com/agent-alice")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/.well-known/aip/agent-alice.json" {
			http.Error(w, "unexpected path "+req.URL.Path, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	}))
	defer srv.Close()

	h := httpResolverWithRewrittenHost(t, srv)
	doc, err := h.Resolve(context.Background(), "aip:web:example.com/agent-alice")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if doc.ID != "aip:web:example.com/agent-alice" {
		t.Errorf("resolved id = %q", doc.ID)
	}
}

func TestHTTPResolver_Resolve_404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.NotFound(w, req)
	}))
	defer srv.Close()

	h := httpResolverWithRewrittenHost(t, srv)
	_, err := h.Resolve(context.Background(), "aip:web:example.com/missing")
	if !errors.Is(err, ErrIdentityNotFound) {
		t.Errorf("expected ErrIdentityNotFound, got %v", err)
	}
}

func TestHTTPResolver_Resolve_500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	h := httpResolverWithRewrittenHost(t, srv)
	_, err := h.Resolve(context.Background(), "aip:web:example.com/oops")
	if err == nil {
		t.Fatal("expected error on 500, got nil")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("expected error to mention status 500; got %v", err)
	}
}

func TestHTTPResolver_Resolve_RejectsKeyForm(t *testing.T) {
	h := NewHTTPResolver()
	_, err := h.Resolve(context.Background(), "aip:key:ed25519:abc")
	if err == nil {
		t.Fatal("expected error for key-form id")
	}
}

func TestHTTPResolver_Resolve_TransportError(t *testing.T) {
	h := &HTTPResolver{
		Client: &http.Client{
			Timeout: 100 * time.Millisecond,
			Transport: errTransport{},
		},
	}
	_, err := h.Resolve(context.Background(), "aip:web:example.com/a")
	if err == nil {
		t.Fatal("expected transport error, got nil")
	}
}

type errTransport struct{}

func (errTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, io.ErrUnexpectedEOF
}

// --- ParseDocument error branches ---

func TestParseDocument_InvalidJSON(t *testing.T) {
	_, err := ParseDocument([]byte(`{this is not json`))
	if err == nil {
		t.Fatal("expected parse error")
	}
}

func TestParseDocument_BadKeyBase64(t *testing.T) {
	raw := []byte(`{
		"aip":"1.0",
		"id":"aip:web:example.com/a",
		"public_keys":[{"kid":"k1","alg":"ed25519","key":"!!!not-valid-base64!!!","valid_from":"2026-01-01T00:00:00Z","valid_until":"2026-12-31T00:00:00Z"}],
		"document_signature":"AA"
	}`)
	_, err := ParseDocument(raw)
	if err == nil {
		t.Fatal("expected key-decode error")
	}
}

func TestParseDocument_StandardBase64Fallback(t *testing.T) {
	// A key base64-encoded with padding — ParseDocument's fallback path.
	keyBytes := make([]byte, 32)
	for i := range keyBytes {
		keyBytes[i] = byte(i)
	}
	padded := base64.URLEncoding.EncodeToString(keyBytes) // with padding
	raw := []byte(fmt.Sprintf(`{
		"aip":"1.0",
		"id":"aip:web:example.com/a",
		"public_keys":[{"kid":"k1","alg":"ed25519","key":"%s","valid_from":"2026-01-01T00:00:00Z","valid_until":"2026-12-31T00:00:00Z"}],
		"document_signature":"AA"
	}`, padded))
	d, err := ParseDocument(raw)
	if err != nil {
		t.Fatalf("unexpected error on padded base64: %v", err)
	}
	if len(d.PublicKeys[0].Key) != 32 {
		t.Errorf("key length = %d, want 32", len(d.PublicKeys[0].Key))
	}
}

// --- checkID06 and signingKeyCandidates branches ---

func TestValidate_ID06_RawMissing(t *testing.T) {
	// Build a Document whose Raw is nil — simulates someone constructing
	// Document by hand instead of via ParseDocument.
	d := &Document{
		AIP: "1.0",
		ID:  "aip:web:example.com/a",
		PublicKeys: []PublicKey{{
			KID: "k1", Alg: "ed25519",
			ValidFrom:  fixedNow().Add(-1 * time.Hour),
			ValidUntil: fixedNow().Add(1 * time.Hour),
		}},
		DocumentSignature: "AA",
	}
	r := Validate(context.Background(), d, Options{Now: fixedNow})
	if !hasFinding(r, CheckID06, report.SeverityError) {
		t.Errorf("expected ID-06 ERROR when Raw empty; got %+v", r.Findings)
	}
}

func TestValidate_ID06_EmptySignature(t *testing.T) {
	raw, priv, _ := mintDoc(t, "aip:web:example.com/a")
	raw = resign(t, raw, priv, func(tree map[string]any) {}) // no-op mutation, but keep valid sig
	// Now replace signature with empty string, NOT re-signing.
	raw = mutateRaw(t, raw, func(tree map[string]any) {
		tree["document_signature"] = ""
	})
	doc := reparse(t, raw)
	r := Validate(context.Background(), doc, Options{Now: fixedNow})
	if !hasFinding(r, CheckID06, report.SeverityError) {
		t.Errorf("expected ID-06 ERROR for empty signature; got %+v", r.Findings)
	}
}

func TestValidate_ID06_BadBase64Signature(t *testing.T) {
	raw, _, _ := mintDoc(t, "aip:web:example.com/a")
	raw = mutateRaw(t, raw, func(tree map[string]any) {
		tree["document_signature"] = "!!!not-base64!!!"
	})
	doc := reparse(t, raw)
	r := Validate(context.Background(), doc, Options{Now: fixedNow})
	if !hasFinding(r, CheckID06, report.SeverityError) {
		t.Errorf("expected ID-06 ERROR for non-base64 sig; got %+v", r.Findings)
	}
}

func TestValidate_ID06_SigningKIDMatches(t *testing.T) {
	raw, priv, _ := mintDoc(t, "aip:web:example.com/a")
	raw = resign(t, raw, priv, func(tree map[string]any) {
		tree["document_signing_kid"] = "k1" // the key minted by mintDoc
	})
	doc := reparse(t, raw)
	r := Validate(context.Background(), doc, Options{Now: fixedNow})
	if hasFinding(r, CheckID06, report.SeverityError) {
		t.Errorf("ID-06 should pass when signing_kid matches; got %+v", r.Findings)
	}
}

func TestValidate_ID06_SigningKIDMissing(t *testing.T) {
	raw, priv, _ := mintDoc(t, "aip:web:example.com/a")
	raw = resign(t, raw, priv, func(tree map[string]any) {
		tree["document_signing_kid"] = "not-a-known-kid"
	})
	doc := reparse(t, raw)
	r := Validate(context.Background(), doc, Options{Now: fixedNow})
	if !hasFinding(r, CheckID06, report.SeverityError) {
		t.Errorf("expected ID-06 ERROR when signing_kid names no known key; got %+v", r.Findings)
	}
}

func TestValidate_ID06_NoEd25519Keys(t *testing.T) {
	raw, priv, _ := mintDoc(t, "aip:web:example.com/a")
	raw = resign(t, raw, priv, func(tree map[string]any) {
		// Replace the ed25519 key with something else.
		tree["public_keys"] = []any{
			map[string]any{
				"kid":         "k1",
				"alg":         "rsa",
				"key":         "aGVsbG8",
				"valid_from":  fixedNow().Add(-1 * time.Hour).Format(time.RFC3339),
				"valid_until": fixedNow().Add(1 * time.Hour).Format(time.RFC3339),
			},
		}
	})
	doc := reparse(t, raw)
	r := Validate(context.Background(), doc, Options{Now: fixedNow})
	if !hasFinding(r, CheckID06, report.SeverityError) {
		t.Errorf("expected ID-06 ERROR when no ed25519 keys present; got %+v", r.Findings)
	}
}

// --- JCS branch coverage ---

func TestCanonicalize_Booleans(t *testing.T) {
	got, err := Canonicalize([]byte(`{"yes":true,"no":false,"zilch":null}`))
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	want := `{"no":false,"yes":true,"zilch":null}`
	if string(got) != want {
		t.Errorf("got %q, want %q", string(got), want)
	}
}

func TestCanonicalize_TrailingData(t *testing.T) {
	_, err := Canonicalize([]byte(`{"a":1}  {"b":2}`))
	if err == nil {
		t.Fatal("expected trailing-data error")
	}
}

func TestCanonicalize_InvalidJSON(t *testing.T) {
	_, err := Canonicalize([]byte(`{not-valid`))
	if err == nil {
		t.Fatal("expected parse error")
	}
}

func TestCanonicalize_NegativeZero(t *testing.T) {
	got, err := Canonicalize([]byte(`{"n":-0}`))
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	// -0 must serialize as 0 per RFC 8785 §3.2.2.3.
	if string(got) != `{"n":0}` {
		t.Errorf("got %q, want %q", string(got), `{"n":0}`)
	}
}

func TestCanonicalize_FloatPath(t *testing.T) {
	got, err := Canonicalize([]byte(`{"n":1.5}`))
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if string(got) != `{"n":1.5}` {
		t.Errorf("got %q, want %q", string(got), `{"n":1.5}`)
	}
}

func TestCanonicalize_ControlCharEscape(t *testing.T) {
	// U+0001 must be emitted as \u0001.
	in := []byte(`{"k":"\u0001"}`)
	got, err := Canonicalize(in)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	want := `{"k":"\u0001"}`
	if string(got) != want {
		t.Errorf("got %q, want %q", string(got), want)
	}
}

func TestCanonicalize_BackslashAndBackspace(t *testing.T) {
	// Exercises \\ and \b arms of writeString.
	in := []byte(`{"k":"a\\b\bc\fd"}`)
	got, err := Canonicalize(in)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	want := `{"k":"a\\b\bc\fd"}`
	if string(got) != want {
		t.Errorf("got %q, want %q", string(got), want)
	}
}

// --- Validate defensive: nil input ---

func TestValidate_NilDocument(t *testing.T) {
	r := Validate(context.Background(), nil, Options{Now: fixedNow})
	if !hasFinding(r, CheckID01, report.SeverityError) {
		t.Errorf("expected ID-01 ERROR for nil doc; got %+v", r.Findings)
	}
}

func TestValidate_DefaultNow(t *testing.T) {
	// Passing Options{} (Now=nil) should not panic; it should use
	// time.Now and, for a freshly minted doc with 24h validity, pass.
	raw, _, _ := mintDoc(t, "aip:web:example.com/a")
	doc := reparse(t, raw)
	r := Validate(context.Background(), doc, Options{}) // Now=nil
	if r.HasErrors() {
		t.Errorf("expected no errors with default Now; got %+v", r.Findings)
	}
}

// --- MapResolver guards ---

func TestNewMapResolver_SkipsNilAndEmptyID(t *testing.T) {
	good := &Document{ID: "aip:web:example.com/a"}
	empty := &Document{ID: ""}
	m := NewMapResolver(nil, empty, good)
	if _, ok := m.Docs["aip:web:example.com/a"]; !ok {
		t.Error("good document not stored")
	}
	if len(m.Docs) != 1 {
		t.Errorf("expected 1 entry, got %d", len(m.Docs))
	}
}

// --- writeNumber defensive-branch coverage ---
//
// These branches guard against callers that reach writeNumber with
// values json.Decoder's UseNumber() would never produce (infinity,
// NaN, unparseable strings). They're real bugs-in-the-making protection,
// not dead code, so we exercise them directly rather than deleting them.

func TestWriteNumber_ParseError(t *testing.T) {
	var buf bytes.Buffer
	err := writeNumber(&buf, "not-a-number")
	if err == nil {
		t.Fatal("expected parse error for non-numeric input")
	}
}

func TestWriteNumber_Infinity(t *testing.T) {
	// strconv.ParseFloat accepts "Inf" — JCS must refuse it.
	var buf bytes.Buffer
	err := writeNumber(&buf, "Inf")
	if err == nil {
		t.Fatal("expected error for infinity")
	}
}

func TestWriteNumber_NaN(t *testing.T) {
	var buf bytes.Buffer
	err := writeNumber(&buf, "NaN")
	if err == nil {
		t.Fatal("expected error for NaN")
	}
}
