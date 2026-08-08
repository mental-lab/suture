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
