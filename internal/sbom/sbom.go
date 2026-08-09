// Package sbom extracts package purls from SBOM documents produced by
// common generators: Syft (syft-json), SPDX JSON, and CycloneDX JSON.
// Format is auto-detected per document so callers can pass whatever their
// existing tooling emits.
package sbom

import (
	"encoding/json"
	"fmt"
	"strings"
)

// PURLs parses one SBOM document and returns the package purls it contains
// (versions stripped). Returns an error if the document matches no known
// SBOM format.
func PURLs(data []byte) ([]string, error) {
	var probe struct {
		Artifacts  json.RawMessage `json:"artifacts"`  // Syft
		Packages   json.RawMessage `json:"packages"`   // SPDX
		Components json.RawMessage `json:"components"` // CycloneDX
		BOMFormat  string          `json:"bomFormat"`  // CycloneDX marker
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("not JSON: %w", err)
	}
	switch {
	case probe.Artifacts != nil:
		return parseSyft(probe.Artifacts)
	case probe.BOMFormat != "" || probe.Components != nil:
		return parseCycloneDX(data)
	case probe.Packages != nil:
		return parseSPDX(probe.Packages)
	}
	return nil, fmt.Errorf("unrecognized SBOM format (want Syft, SPDX, or CycloneDX JSON)")
}

// parseSyft reads syft-json: {"artifacts": [{"purl": "..."}, ...]}.
func parseSyft(raw json.RawMessage) ([]string, error) {
	var artifacts []struct {
		PURL string `json:"purl"`
	}
	if err := json.Unmarshal(raw, &artifacts); err != nil {
		return nil, fmt.Errorf("parse Syft artifacts: %w", err)
	}
	var out []string
	for _, a := range artifacts {
		if p := StripVersion(a.PURL); p != "" {
			out = append(out, p)
		}
	}
	return out, nil
}

// parseSPDX reads SPDX JSON: {"packages": [{"externalRefs":
// [{"referenceType": "purl", "referenceLocator": "pkg:..."}]}]}.
func parseSPDX(raw json.RawMessage) ([]string, error) {
	var pkgs []struct {
		ExternalRefs []struct {
			Type    string `json:"referenceType"`
			Locator string `json:"referenceLocator"`
		} `json:"externalRefs"`
	}
	if err := json.Unmarshal(raw, &pkgs); err != nil {
		return nil, fmt.Errorf("parse SPDX packages: %w", err)
	}
	var out []string
	for _, p := range pkgs {
		for _, ref := range p.ExternalRefs {
			if ref.Type == "purl" {
				if s := StripVersion(ref.Locator); s != "" {
					out = append(out, s)
				}
			}
		}
	}
	return out, nil
}

// parseCycloneDX reads CycloneDX JSON: {"components": [{"purl": "..."}]}.
func parseCycloneDX(data []byte) ([]string, error) {
	var doc struct {
		Components []struct {
			PURL string `json:"purl"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse CycloneDX components: %w", err)
	}
	var out []string
	for _, c := range doc.Components {
		if p := StripVersion(c.PURL); p != "" {
			out = append(out, p)
		}
	}
	return out, nil
}

// StripVersion drops the @version and ?qualifiers segments, leaving e.g.
// "pkg:pypi/werkzeug".
func StripVersion(purl string) string {
	if !strings.HasPrefix(purl, "pkg:") {
		return ""
	}
	if i := strings.IndexAny(purl, "@?#"); i >= 0 {
		return purl[:i]
	}
	return purl
}
