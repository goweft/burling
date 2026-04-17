package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/goweft/burling/internal/identity"
)

// runCaptured invokes runCommand with fresh tempfiles for stdout and
// stderr, then reads them back so tests can assert on output. Using
// real *os.File (rather than bytes.Buffer with an io.Writer seam)
// matches what runCommand actually takes and avoids leaking a test-
// only abstraction into main.go's signature.
func runCaptured(t *testing.T, args ...string) (exit int, stdout, stderr string) {
	t.Helper()
	dir := t.TempDir()
	outPath := filepath.Join(dir, "stdout")
	errPath := filepath.Join(dir, "stderr")
	outF, err := os.Create(outPath)
	if err != nil {
		t.Fatalf("create stdout: %v", err)
	}
	errF, err := os.Create(errPath)
	if err != nil {
		t.Fatalf("create stderr: %v", err)
	}
	exit = runCommand(context.Background(), args, outF, errF)
	_ = outF.Close()
	_ = errF.Close()
	outB, _ := os.ReadFile(outPath)
	errB, _ := os.ReadFile(errPath)
	return exit, string(outB), string(errB)
}

// writeTempToken writes raw to a temp file and returns its path.
func writeTempToken(t *testing.T, raw string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "token-*.txt")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	if _, err := io.WriteString(f, raw); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	_ = f.Close()
	return f.Name()
}

// writeTempIDDoc writes raw identity-document bytes to a temp file
// and returns its path.
func writeTempIDDoc(t *testing.T, raw []byte) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "id-*.json")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	if _, err := f.Write(raw); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	_ = f.Close()
	return f.Name()
}

// mintSignedIdentity builds an identity document and returns both the
// raw bytes and the keypair so callers can sign compact tokens against
// it. Mirrors the fixture shape used in internal/compact and
// internal/identity tests.
func mintSignedIdentity(t *testing.T, id string) (raw []byte, pub ed25519.PublicKey, priv ed25519.PrivateKey) {
	t.Helper()
	var err error
	pub, priv, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	now := time.Now()
	tree := map[string]any{
		"aip": "1.0",
		"id":  id,
		"public_keys": []any{
			map[string]any{
				"kid":         "k1",
				"alg":         "ed25519",
				"key":         base64.RawURLEncoding.EncodeToString(pub),
				"valid_from":  now.Add(-1 * time.Hour).Format(time.RFC3339),
				"valid_until": now.Add(24 * time.Hour).Format(time.RFC3339),
			},
		},
	}
	stripped, _ := json.Marshal(tree)
	canon, err := identity.Canonicalize(stripped)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	tree["document_signature"] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, canon))
	raw, err = json.Marshal(tree)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw, pub, priv
}

// mintCompactToken builds a valid compact token signed by priv with
// the given issuer id and kid. Windows are anchored at time.Now()
// because the CLI uses a real clock.
func mintCompactToken(t *testing.T, iss, kid string, priv ed25519.PrivateKey) string {
	t.Helper()
	now := time.Now()
	header := map[string]any{"alg": "EdDSA", "typ": "aip-ibct+jwt", "kid": kid}
	payload := map[string]any{
		"iss":        iss,
		"sub":        "aip:web:example.com/agent-cli-test",
		"aud":        []string{"aip:web:example.com/mcp-cli-test"},
		"exp":        now.Add(30 * time.Minute).Unix(),
		"nbf":        now.Add(-1 * time.Minute).Unix(),
		"jti":        "01HZ5N8Q3R4TV6W7X8Y9Z0ABCD",
		"scope":      map[string]any{"tools": []string{"search"}},
		"invocation": map[string]any{"session_id": "sess-cli"},
	}
	hdrJSON, _ := json.Marshal(header)
	plJSON, _ := json.Marshal(payload)
	hdr := base64.RawURLEncoding.EncodeToString(hdrJSON)
	pl := base64.RawURLEncoding.EncodeToString(plJSON)
	signingInput := hdr + "." + pl
	sig := ed25519.Sign(priv, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// --- dispatch tests ---

func TestRun_NoArgs_PrintsUsageAndExits2(t *testing.T) {
	exit, _, stderr := runCaptured(t)
	if exit != 2 {
		t.Errorf("exit = %d, want 2", exit)
	}
	if !strings.Contains(stderr, "Usage") {
		t.Errorf("stderr should contain usage; got %q", stderr)
	}
}

func TestRun_UnknownCommand(t *testing.T) {
	exit, _, stderr := runCaptured(t, "frobnicate")
	if exit != 2 {
		t.Errorf("exit = %d, want 2", exit)
	}
	if !strings.Contains(stderr, "unknown command") {
		t.Errorf("stderr should name unknown cmd; got %q", stderr)
	}
}

func TestRun_Help(t *testing.T) {
	exit, stdout, _ := runCaptured(t, "help")
	if exit != 0 {
		t.Errorf("exit = %d, want 0", exit)
	}
	if !strings.Contains(stdout, "Usage") {
		t.Errorf("stdout should contain usage; got %q", stdout)
	}
}

func TestRun_Version(t *testing.T) {
	exit, stdout, _ := runCaptured(t, "version")
	if exit != 0 {
		t.Errorf("exit = %d, want 0", exit)
	}
	if !strings.HasPrefix(stdout, "burling ") {
		t.Errorf("stdout = %q, want prefix 'burling '", stdout)
	}
}

// --- audit-chain (stub) ---

func TestCmdAuditChain_StubInfoPath(t *testing.T) {
	tok := writeTempToken(t, "does.not.matter")
	exit, stdout, _ := runCaptured(t, "audit-chain", tok)
	if exit != 0 {
		t.Errorf("exit = %d, want 0 (stub emits INFO only)", exit)
	}
	if !strings.Contains(stdout, "chained-mode validation deferred") {
		t.Errorf("stdout should mention deferral; got %q", stdout)
	}
}

func TestCmdAuditChain_MissingArg(t *testing.T) {
	exit, _, stderr := runCaptured(t, "audit-chain")
	if exit != 2 {
		t.Errorf("exit = %d, want 2", exit)
	}
	if !strings.Contains(stderr, "usage:") {
		t.Errorf("stderr should show usage; got %q", stderr)
	}
}

// --- validate-identity ---

func TestCmdValidateIdentity_FileOK(t *testing.T) {
	raw, _, _ := mintSignedIdentity(t, "aip:key:ed25519:"+base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	path := writeTempIDDoc(t, raw)
	exit, stdout, stderr := runCaptured(t, "validate-identity", path)
	// Key-form ID means ID-08 is skipped silently, and every other
	// check should pass. Exit 0.
	if exit != 0 {
		t.Errorf("exit = %d, want 0; stderr=%q", exit, stderr)
	}
	if !strings.Contains(stdout, "PASS") && !strings.Contains(stdout, "No findings") {
		t.Errorf("expected PASS or no findings; stdout=%q", stdout)
	}
}

func TestCmdValidateIdentity_TamperedFile(t *testing.T) {
	raw, _, _ := mintSignedIdentity(t, "aip:key:ed25519:"+base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	// Flip a byte in the signature portion so ID-06 fires.
	var tree map[string]any
	_ = json.Unmarshal(raw, &tree)
	sig := tree["document_signature"].(string)
	sigBytes, _ := base64.RawURLEncoding.DecodeString(sig)
	sigBytes[0] ^= 0xFF
	tree["document_signature"] = base64.RawURLEncoding.EncodeToString(sigBytes)
	tampered, _ := json.Marshal(tree)
	path := writeTempIDDoc(t, tampered)

	exit, stdout, _ := runCaptured(t, "validate-identity", path)
	if exit != 1 {
		t.Errorf("exit = %d, want 1 on ID-06 failure", exit)
	}
	if !strings.Contains(stdout, "ID-06") {
		t.Errorf("stdout should mention ID-06; got %q", stdout)
	}
}

func TestCmdValidateIdentity_URL(t *testing.T) {
	// URL-based path needs a real HTTP server because fetchURL uses
	// http.DefaultClient. httptest.Server gives us one.
	raw, _, _ := mintSignedIdentity(t, "aip:web:example.com/cli-test")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	}))
	defer srv.Close()

	// The URL we pass goes to fetchURL. But then the identity document
	// under validation has id "aip:web:example.com/cli-test" and the
	// HTTPResolver used by ID-08 will try to resolve that to the real
	// example.com well-known URL, which will fail. So we expect exit 1
	// with an ID-08 ERROR — and the PASS of every other check proves
	// the CLI URL-fetch path worked.
	exit, stdout, _ := runCaptured(t, "validate-identity", srv.URL)
	if exit != 1 {
		t.Errorf("exit = %d, want 1 (ID-08 will fail against real example.com)", exit)
	}
	// ID-01..ID-07, ID-09 should all pass; ID-08 is the expected fail.
	if !strings.Contains(stdout, "ID-08") {
		t.Errorf("stdout should mention ID-08; got %q", stdout)
	}
}

func TestCmdValidateIdentity_MissingFile(t *testing.T) {
	exit, _, stderr := runCaptured(t, "validate-identity", "/nonexistent/path/xyz.json")
	if exit != 2 {
		t.Errorf("exit = %d, want 2", exit)
	}
	if !strings.Contains(stderr, "validate-identity") {
		t.Errorf("stderr should mention command; got %q", stderr)
	}
}

// --- validate (compact token) ---
//
// A fully-green validate end-to-end test requires the issuer's
// identity document to be resolvable at its well-known URL, which
// means either mocking DNS or accepting that CM-03/04 will fail
// against a URL nobody can resolve. We accept the failure: the
// important assertion is that the CLI wiring works, produces a
// report, and the exit code matches the severity.

func TestCmdValidate_TokenWithUnresolvableIssuer(t *testing.T) {
	_, _, priv := mintSignedIdentity(t, "aip:web:nonexistent.invalid/agent")
	tokStr := mintCompactToken(t, "aip:web:nonexistent.invalid/agent", "k1", priv)
	path := writeTempToken(t, tokStr)

	exit, stdout, _ := runCaptured(t, "validate", path)
	// CM-03 will fail because the issuer URL is unresolvable. Every
	// other check should pass. Exit 1.
	if exit != 1 {
		t.Errorf("exit = %d, want 1 (CM-03 fails on unresolvable issuer)", exit)
	}
	if !strings.Contains(stdout, "CM-03") {
		t.Errorf("stdout should mention CM-03; got %q", stdout)
	}
	// Confirm CM-01/02 passed — those are structural checks that don't
	// depend on resolution.
	if strings.Contains(stdout, "ERROR   [CM-01]") {
		t.Errorf("CM-01 should not be ERROR on a well-formed token; got %q", stdout)
	}
}

func TestCmdValidate_GarbageTokenFile(t *testing.T) {
	path := writeTempToken(t, "not.a.valid.jwt")
	exit, _, stderr := runCaptured(t, "validate", path)
	if exit != 2 {
		t.Errorf("exit = %d, want 2 (parse failure)", exit)
	}
	if !strings.Contains(stderr, "parse token") {
		t.Errorf("stderr should mention parse; got %q", stderr)
	}
}

func TestCmdValidate_JSONFormat(t *testing.T) {
	_, _, priv := mintSignedIdentity(t, "aip:web:nonexistent.invalid/agent")
	tokStr := mintCompactToken(t, "aip:web:nonexistent.invalid/agent", "k1", priv)
	path := writeTempToken(t, tokStr)

	_, stdout, _ := runCaptured(t, "validate", "--format", "json", path)
	// Just prove it's valid JSON and contains the expected top-level
	// keys — the CM-03 failure is fine.
	var got map[string]any
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout)
	}
	for _, key := range []string{"target", "burling_version", "spec_version", "findings"} {
		if _, ok := got[key]; !ok {
			t.Errorf("JSON output missing key %q", key)
		}
	}
}

// --- lint ---

func TestCmdLint_IncludesStubFindings(t *testing.T) {
	_, _, priv := mintSignedIdentity(t, "aip:web:nonexistent.invalid/agent")
	tokStr := mintCompactToken(t, "aip:web:nonexistent.invalid/agent", "k1", priv)
	path := writeTempToken(t, tokStr)

	// Default lint output is JSON.
	_, stdout, _ := runCaptured(t, "lint", path)
	// All five non-chained stub checks should appear: SA-00, BD-00,
	// DC-00, CB-00, MB-00. Chained intentionally NOT in lint (audit-
	// chain is the dedicated command for it).
	for _, id := range []string{"SA-00", "BD-00", "DC-00", "CB-00", "MB-00"} {
		if !strings.Contains(stdout, id) {
			t.Errorf("lint output missing %s; got %q", id, stdout)
		}
	}
	if strings.Contains(stdout, "CH-00") {
		t.Errorf("lint output should NOT contain CH-00 (reserved for audit-chain); got %q", stdout)
	}
}

// --- --strict behavior ---

func TestStrict_PromotesWarning(t *testing.T) {
	// An identity doc with expires in the past → ID-07 WARNING.
	// Under --strict, exit code should be 1.
	now := time.Now()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	past := now.Add(-1 * time.Hour).Format(time.RFC3339)
	tree := map[string]any{
		"aip": "1.0",
		"id":  "aip:key:ed25519:" + base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		"public_keys": []any{
			map[string]any{
				"kid":         "k1",
				"alg":         "ed25519",
				"key":         base64.RawURLEncoding.EncodeToString(pub),
				"valid_from":  now.Add(-1 * time.Hour).Format(time.RFC3339),
				"valid_until": now.Add(24 * time.Hour).Format(time.RFC3339),
			},
		},
		"expires": past,
	}
	stripped, _ := json.Marshal(tree)
	canon, _ := identity.Canonicalize(stripped)
	tree["document_signature"] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, canon))
	raw, _ := json.Marshal(tree)
	path := writeTempIDDoc(t, raw)

	// Without --strict: WARNING only, exit 0.
	exit, _, _ := runCaptured(t, "validate-identity", path)
	if exit != 0 {
		t.Errorf("without --strict: exit = %d, want 0", exit)
	}
	// With --strict: exit 1.
	exit, _, _ = runCaptured(t, "validate-identity", "--strict", path)
	if exit != 1 {
		t.Errorf("with --strict: exit = %d, want 1", exit)
	}
}

// --- format flag validation ---

func TestFormat_Unknown(t *testing.T) {
	tok := writeTempToken(t, "does.not.matter")
	exit, _, stderr := runCaptured(t, "audit-chain", "--format", "xml", tok)
	if exit != 2 {
		t.Errorf("exit = %d, want 2 for unknown format", exit)
	}
	if !strings.Contains(stderr, "unknown --format") {
		t.Errorf("stderr should complain about format; got %q", stderr)
	}
}

// Smoke: audit-chain JSON output is actually valid JSON.
func TestCmdAuditChain_JSONIsParseable(t *testing.T) {
	tok := writeTempToken(t, "x")
	_, stdout, _ := runCaptured(t, "audit-chain", "--format", "json", tok)
	var got map[string]any
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout)
	}
	findings, ok := got["findings"].([]any)
	if !ok || len(findings) == 0 {
		t.Errorf("expected non-empty findings array; got %+v", got)
	}
}

// Guard: text output ordering is severity-descending.
func TestRenderText_SortsSeverityDescending(t *testing.T) {
	// We go through audit-chain (all INFO) and a tampered identity
	// (one ERROR) separately — audit-chain alone can't test ordering
	// because all its findings are the same severity. This test
	// instead proves the rendering path doesn't crash on mixed-
	// severity input. Exhaustive ordering is unit-tested at the
	// render level; here we only confirm the CLI wires it up.
	raw, _, _ := mintSignedIdentity(t, "aip:key:ed25519:"+base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	// Tamper signature → one ERROR finding among INFOs from the
	// (ID-08-skipped) path.
	var tree map[string]any
	_ = json.Unmarshal(raw, &tree)
	tree["document_signature"] = base64.RawURLEncoding.EncodeToString([]byte{0, 1, 2})
	bad, _ := json.Marshal(tree)
	path := writeTempIDDoc(t, bad)

	_, stdout, _ := runCaptured(t, "validate-identity", path)
	if !bytes.Contains([]byte(stdout), []byte("ERROR")) {
		t.Errorf("expected ERROR line; got %q", stdout)
	}
	// ERROR should appear before any INFO in the output.
	ei := strings.Index(stdout, "ERROR")
	ii := strings.Index(stdout, "INFO")
	if ei < 0 {
		t.Fatal("no ERROR in output")
	}
	if ii >= 0 && ii < ei {
		t.Errorf("INFO appeared before ERROR; ordering wrong. stdout=%q", stdout)
	}
}

