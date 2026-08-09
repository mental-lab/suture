// Package feed fetches the Chainguard Libraries OpenVEX feed and builds the
// fix cache consumed by the policy gate (as an OPA data document) and by the
// remediation advisor.
package feed

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const DefaultBaseURL = "https://libraries.cgr.dev/openvex/v1"

type Client struct {
	BaseURL string
	HTTP    *http.Client
}

func New() *Client {
	return &Client{
		BaseURL: DefaultBaseURL,
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
}

// Document is the subset of an OpenVEX document this tool reads. Raw bytes
// are preserved separately when materializing documents for Grype's --vex.
type Document struct {
	Statements []Statement `json:"statements"`
}

type Statement struct {
	Status        string `json:"status"`
	Vulnerability struct {
		Name    string   `json:"name"`
		Aliases []string `json:"aliases"`
	} `json:"vulnerability"`
	Products []struct {
		Identifiers struct {
			PURL string `json:"purl"`
		} `json:"identifiers"`
	} `json:"products"`
}

func ParseDocument(raw []byte) (*Document, error) {
	var doc Document
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse OpenVEX document: %w", err)
	}
	return &doc, nil
}

// Index lists the OpenVEX document IDs in the feed
// (e.g. "pypi/werkzeug.openvex.json").
func (c *Client) Index(ctx context.Context) ([]string, error) {
	var body struct {
		Entries []struct {
			ID string `json:"id"`
		} `json:"entries"`
	}
	if err := c.get(ctx, c.BaseURL+"/all.json", &body); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(body.Entries))
	for _, e := range body.Entries {
		ids = append(ids, e.ID)
	}
	return ids, nil
}

// FetchRaw fetches one per-package OpenVEX document by feed entry ID and
// returns the raw bytes.
func (c *Client) FetchRaw(ctx context.Context, id string) ([]byte, error) {
	var raw json.RawMessage
	if err := c.get(ctx, c.BaseURL+"/"+url.PathEscape(id), &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

func (c *Client) get(ctx context.Context, u string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

// Cache maps a version-less package purl to vulnerability ID → fixed purls:
//
//	{"pkg:pypi/werkzeug": {"CVE-2026-27171": ["pkg:pypi/werkzeug@2.2.3%2Bcgr.1"]}}
//
// Only status=fixed statements are indexed, keyed by every identifier (CVE,
// GHSA, …) since scanners disagree on which ID they surface.
type Cache map[string]map[string][]string

// Index folds one OpenVEX document into the cache.
func (c Cache) Index(doc *Document) {
	for _, stmt := range doc.Statements {
		if stmt.Status != "fixed" {
			continue
		}
		ids := append([]string{stmt.Vulnerability.Name}, stmt.Vulnerability.Aliases...)
		for _, product := range stmt.Products {
			purl := product.Identifiers.PURL
			if purl == "" {
				continue
			}
			pkg := strings.SplitN(purl, "@", 2)[0]
			if c[pkg] == nil {
				c[pkg] = map[string][]string{}
			}
			for _, id := range ids {
				if id != "" {
					c[pkg][id] = append(c[pkg][id], purl)
				}
			}
		}
	}
}

// DocKey maps a purl (with or without version) to the feed's document key,
// e.g. "pkg:pypi/werkzeug" → "pypi/werkzeug" and
// "pkg:maven/org.apache.logging.log4j/log4j-core@2.1" →
// "maven/org.apache.logging.log4j_log4j-core". Scoped names (npm
// "@scope/name") are percent-decoded and joined with "_", matching the
// feed's naming convention. The key is returned un-normalized; compare
// with MatchKeys. Returns false for malformed purls.
func DocKey(purl string) (string, bool) {
	rest, ok := strings.CutPrefix(purl, "pkg:")
	if !ok {
		return "", false
	}
	if i := strings.IndexAny(rest, "@?#"); i >= 0 {
		rest = rest[:i]
	}
	parts := strings.Split(rest, "/")
	if len(parts) < 2 {
		return "", false
	}
	names := make([]string, 0, len(parts)-1)
	for _, p := range parts[1:] {
		dec, err := url.PathUnescape(p)
		if err != nil {
			return "", false
		}
		names = append(names, dec)
	}
	return parts[0] + "/" + strings.Join(names, "_"), true
}

// MatchKeys reports whether two document keys refer to the same package,
// normalizing the name portion (case and "-"/"_"/"." differences) so purls
// from different SBOM producers match feed entries reliably. A wanted key
// with an empty ecosystem ("pypi/" form omitted, i.e. "werkzeug") matches
// any ecosystem with that name.
func MatchKeys(want, have string) bool {
	wEco, wName := SplitKey(want)
	hEco, hName := SplitKey(have)
	if wEco != "" && wEco != hEco {
		return false
	}
	return NormalizeName(wName) == NormalizeName(hName)
}

// SplitKey splits a document key into ecosystem and name ("pypi/werkzeug" →
// "pypi", "werkzeug"). Keys without a "/" yield an empty ecosystem.
func SplitKey(key string) (eco, name string) {
	eco, name, found := strings.Cut(key, "/")
	if !found {
		return "", key
	}
	return eco, name
}

// NormalizeName canonicalizes a package name for matching: lowercase with
// runs of "-", "_", "." collapsed to "-" (PEP 503-style, applied to all
// ecosystems since feed matching is fuzzy anyway).
func NormalizeName(name string) string {
	name = strings.ToLower(name)
	var b strings.Builder
	lastDash := false
	for _, r := range name {
		if r == '-' || r == '_' || r == '.' {
			if !lastDash {
				b.WriteByte('-')
			}
			lastDash = true
			continue
		}
		lastDash = false
		b.WriteRune(r)
	}
	return b.String()
}

// KeyFromID strips the ".openvex.json" suffix from a feed entry ID, leaving
// the document key ("pypi/werkzeug").
func KeyFromID(id string) string {
	return strings.TrimSuffix(id, ".openvex.json")
}

// Stats returns (packages, fix mappings) for logging.
func (c Cache) Stats() (pkgs, fixes int) {
	for _, byID := range c {
		pkgs++
		for _, purls := range byID {
			fixes += len(purls)
		}
	}
	return pkgs, fixes
}
