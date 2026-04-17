package identity

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Resolver fetches an identity document by its AIP ID.
//
// Implementations must be safe for concurrent use. A nil Resolver is a
// legal argument to Validate — ID-08 emits an INFO finding rather than
// an ERROR in that case, preferring explicit "skipped" over silent
// failure. See validate.go.
type Resolver interface {
	Resolve(ctx context.Context, id string) (*Document, error)
}

// ErrIdentityNotFound is returned by Resolver implementations when an
// identity document does not exist at the resolved location. ID-08
// treats this as an ERROR finding.
var ErrIdentityNotFound = errors.New("identity document not found")

// MapResolver is an in-memory Resolver used by tests. Safe for
// concurrent reads after construction; do not mutate Docs after
// passing the resolver to Validate.
type MapResolver struct {
	Docs map[string]*Document
}

// NewMapResolver returns a MapResolver seeded with the given documents,
// keyed by their ID field. Documents with empty IDs are skipped.
func NewMapResolver(docs ...*Document) *MapResolver {
	m := &MapResolver{Docs: make(map[string]*Document, len(docs))}
	for _, d := range docs {
		if d == nil || d.ID == "" {
			continue
		}
		m.Docs[d.ID] = d
	}
	return m
}

// Resolve returns the document for id, or ErrIdentityNotFound.
func (m *MapResolver) Resolve(_ context.Context, id string) (*Document, error) {
	d, ok := m.Docs[id]
	if !ok {
		return nil, ErrIdentityNotFound
	}
	return d, nil
}

// HTTPResolver resolves `aip:web:<domain>/<path>` IDs by fetching
// `https://<domain>/.well-known/aip/<path>.json` per §2.3.
//
// Key-form IDs (`aip:key:ed25519:<key>`) are self-describing and ID-08
// skips HTTP resolution for them; HTTPResolver.Resolve will error if
// called with a key-form ID.
//
// TODO(ambiguity-05): §5.4 mandates cache TTL ≤ 5 minutes but gives no
// Cache-Control guidance. HTTPResolver does not cache in v0.1; a
// caching layer should wrap this interface rather than live inside it.
type HTTPResolver struct {
	Client *http.Client
}

// NewHTTPResolver returns an HTTPResolver with a 10-second timeout.
func NewHTTPResolver() *HTTPResolver {
	return &HTTPResolver{
		Client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Resolve fetches and parses the identity document for id.
func (h *HTTPResolver) Resolve(ctx context.Context, id string) (*Document, error) {
	u, err := WebIDToURL(id)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := h.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", u, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrIdentityNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: status %d", u, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return ParseDocument(body)
}

// WebIDToURL converts an `aip:web:<domain>/<path>` identifier to the
// well-known URL defined by §2.3. Returns an error for non-web IDs.
//
// TODO(ambiguity-05): spec is silent on the empty-path case
// (`aip:web:example.com` with no trailing path). The "root.json"
// fallback is a burling choice and should be raised with Prakash.
func WebIDToURL(id string) (string, error) {
	const prefix = "aip:web:"
	if !strings.HasPrefix(id, prefix) {
		return "", fmt.Errorf("not an aip:web: identifier: %q", id)
	}
	rest := strings.TrimPrefix(id, prefix)
	if rest == "" {
		return "", fmt.Errorf("empty authority in %q", id)
	}
	var domain, path string
	if i := strings.Index(rest, "/"); i >= 0 {
		domain = rest[:i]
		path = rest[i+1:]
	} else {
		domain = rest
	}
	if domain == "" {
		return "", fmt.Errorf("empty domain in %q", id)
	}
	if path == "" {
		path = "root"
	}
	u := &url.URL{
		Scheme: "https",
		Host:   domain,
		Path:   "/.well-known/aip/" + path + ".json",
	}
	return u.String(), nil
}

// ParseDocument parses raw JSON bytes into a Document. It preserves
// the raw bytes on Document.Raw so ID-06 can canonicalize the original
// form for signature verification. Public key base64url values are
// decoded eagerly.
func ParseDocument(raw []byte) (*Document, error) {
	var d Document
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("parse document: %w", err)
	}
	d.Raw = append([]byte(nil), raw...)
	for i := range d.PublicKeys {
		pk := &d.PublicKeys[i]
		if pk.KeyBase64 == "" {
			continue
		}
		key, err := base64.RawURLEncoding.DecodeString(pk.KeyBase64)
		if err != nil {
			key, err = base64.URLEncoding.DecodeString(pk.KeyBase64)
			if err != nil {
				return nil, fmt.Errorf("decode key %q: %w", pk.KID, err)
			}
		}
		pk.Key = key
	}
	return &d, nil
}
