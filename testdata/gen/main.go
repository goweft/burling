// Command gen-example generates the committed example fixtures under
// testdata/example/. Run it from the repo root:
//
//	go run ./testdata/gen -outdir testdata/example
//
// The output is:
//
//	identity.json   Fully-valid AIP §2.3 identity document
//	identity-tampered.json
//	                Same document with one byte flipped in the
//	                signature, so ID-06 fires as ERROR.
//	token.jwt       Compact IBCT signed by the identity's k1.
//	token-expired.jwt
//	                Same token with exp one hour in the past.
//
// The private key used to sign is NOT written to disk; the fixtures
// are regenerated fresh on every run (so each invocation produces
// different signatures). Commit the output alongside a note that
// consumers can re-run this tool any time.
//
// Why commit generated fixtures at all? Because the README's worked
// example needs a real file a reader can point the CLI at, and we
// want the README copy-paste to produce the exact output shown.
// Each regeneration means the README's exact output lines may drift;
// the test under cmd/burling handles that by asserting on structure,
// not bytes.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/goweft/burling/internal/identity"
)

func main() {
	outdir := flag.String("outdir", "testdata/example", "output directory")
	flag.Parse()

	if err := os.MkdirAll(*outdir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir: %v\n", err)
		os.Exit(1)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	must(err, "genkey")
	iss := "aip:web:example.com/issuer-alpha"
	now := time.Now()

	// --- identity document ---
	idTree := map[string]any{
		"aip": "1.0",
		"id":  iss,
		"public_keys": []any{
			map[string]any{
				"kid":         "k1",
				"alg":         "ed25519",
				"key":         base64.RawURLEncoding.EncodeToString(pub),
				"valid_from":  now.Add(-1 * time.Hour).Format(time.RFC3339),
				"valid_until": now.Add(365 * 24 * time.Hour).Format(time.RFC3339),
			},
		},
		"expires": now.Add(7 * 24 * time.Hour).Format(time.RFC3339),
	}
	stripped, _ := json.Marshal(idTree)
	canon, err := identity.Canonicalize(stripped)
	must(err, "canonicalize")
	idTree["document_signature"] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, canon))
	idOut, _ := json.MarshalIndent(idTree, "", "  ")
	write(filepath.Join(*outdir, "identity.json"), idOut)

	// Tampered variant: flip one byte of the signature.
	var tampered map[string]any
	_ = json.Unmarshal(idOut, &tampered)
	sig := tampered["document_signature"].(string)
	sigB, _ := base64.RawURLEncoding.DecodeString(sig)
	sigB[0] ^= 0xFF
	tampered["document_signature"] = base64.RawURLEncoding.EncodeToString(sigB)
	tampOut, _ := json.MarshalIndent(tampered, "", "  ")
	write(filepath.Join(*outdir, "identity-tampered.json"), tampOut)

	// --- compact token ---
	tok := mintToken(now, iss, "k1", priv, now.Add(30*time.Minute))
	write(filepath.Join(*outdir, "token.jwt"), []byte(tok+"\n"))

	// Expired variant: exp one hour ago.
	expired := mintToken(now, iss, "k1", priv, now.Add(-1*time.Hour))
	write(filepath.Join(*outdir, "token-expired.jwt"), []byte(expired+"\n"))

	fmt.Fprintf(os.Stderr, "wrote fixtures to %s\n", *outdir)
}

func mintToken(now time.Time, iss, kid string, priv ed25519.PrivateKey, exp time.Time) string {
	header := map[string]any{"alg": "EdDSA", "typ": "aip-ibct+jwt", "kid": kid}
	payload := map[string]any{
		"iss":        iss,
		"sub":        "aip:web:example.com/agent-bob",
		"aud":        []string{"aip:web:example.com/mcp-server"},
		"exp":        exp.Unix(),
		"nbf":        now.Add(-1 * time.Minute).Unix(),
		"jti":        "01HZ5N8Q3R4TV6W7X8Y9Z0ABCD",
		"scope":      map[string]any{"tools": []string{"search", "fetch"}},
		"invocation": map[string]any{"session_id": "sess-example"},
	}
	hdrJSON, _ := json.Marshal(header)
	plJSON, _ := json.Marshal(payload)
	hdr := base64.RawURLEncoding.EncodeToString(hdrJSON)
	pl := base64.RawURLEncoding.EncodeToString(plJSON)
	signingInput := hdr + "." + pl
	sig := ed25519.Sign(priv, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func must(err error, msg string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", msg, err)
		os.Exit(1)
	}
}

func write(path string, data []byte) {
	if err := os.WriteFile(path, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write %s: %v\n", path, err)
		os.Exit(1)
	}
}
