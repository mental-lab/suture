// Package scan parses vulnerability scanner output (Trivy and Grype JSON)
// into normalized findings.
package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Finding is one scanner-reported vulnerability. Aliases carries the other
// identifiers for the same vulnerability (Grype surfaces a GHSA as the
// primary ID with the CVE in relatedVulnerabilities) so feed lookups match
// either form. PURL (version-less) identifies the package ecosystem.
type Finding struct {
	Target     string   `json:"target"`
	ID         string   `json:"id"`
	Severity   string   `json:"severity"`
	CVSSVector string   `json:"cvss_vector,omitempty"`
	Pkg        string   `json:"pkg"`
	Installed  string   `json:"installed"`
	Fixed      string   `json:"fixed,omitempty"`
	PURL       string   `json:"purl,omitempty"`
	Aliases    []string `json:"aliases,omitempty"`
}

// IDs returns every identifier for the finding, primary first.
func (f Finding) IDs() []string {
	return append([]string{f.ID}, f.Aliases...)
}

// LoadDir parses every *.json in dir, auto-detecting Trivy filesystem
// reports and Grype reports per file. Files that match neither are skipped.
func LoadDir(dir string) ([]Finding, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)

	var findings []Finding
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var probe struct {
			Results json.RawMessage `json:"Results"`
			Matches json.RawMessage `json:"matches"`
		}
		if err := json.Unmarshal(data, &probe); err != nil {
			continue
		}
		switch {
		case probe.Results != nil:
			findings = append(findings, parseTrivy(probe.Results)...)
		case probe.Matches != nil:
			findings = append(findings, parseGrype(data)...)
		}
	}
	return findings, nil
}

type trivyResults []struct {
	Target          string `json:"Target"`
	Class           string `json:"Class"`
	Vulnerabilities []struct {
		VulnerabilityID  string `json:"VulnerabilityID"`
		Severity         string `json:"Severity"`
		PkgName          string `json:"PkgName"`
		InstalledVersion string `json:"InstalledVersion"`
		FixedVersion     string `json:"FixedVersion"`
		CVSS             map[string]struct {
			V3Vector  string `json:"V3Vector"`
			V4Vector  string `json:"V4Vector"`
			V40Vector string `json:"V40Vector"`
		} `json:"CVSS"`
		PkgIdentifier struct {
			PURL string `json:"PURL"`
		} `json:"PkgIdentifier"`
	} `json:"Vulnerabilities"`
}

func parseTrivy(raw json.RawMessage) []Finding {
	var results trivyResults
	if err := json.Unmarshal(raw, &results); err != nil {
		return nil
	}
	var findings []Finding
	for _, r := range results {
		// OS packages (debian/wolfi/etc.) can never have a Chainguard
		// Libraries fix — they belong to the image/OS story, not the
		// advisor. Skipping them keeps image-scan reports readable.
		if r.Class == "os-pkgs" {
			continue
		}
		for _, v := range r.Vulnerabilities {
			var vectors []string
			var sources []string
			for source := range v.CVSS {
				sources = append(sources, source)
			}
			sort.Strings(sources)
			for _, source := range sources {
				entry := v.CVSS[source]
				vectors = append(vectors, entry.V40Vector, entry.V4Vector, entry.V3Vector)
			}
			findings = append(findings, Finding{
				Target:     orDefault(r.Target, "unknown"),
				ID:         orDefault(v.VulnerabilityID, "UNKNOWN"),
				Severity:   strings.ToUpper(orDefault(v.Severity, "UNKNOWN")),
				CVSSVector: preferredCVSS(vectors),
				Pkg:        orDefault(v.PkgName, "?"),
				Installed:  orDefault(v.InstalledVersion, "?"),
				Fixed:      v.FixedVersion,
				PURL:       stripPurlVersion(v.PkgIdentifier.PURL),
			})
		}
	}
	return findings
}

type grypeReport struct {
	Source  json.RawMessage `json:"source"`
	Matches []struct {
		Vulnerability struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
			CVSS     []struct {
				Vector string `json:"vector"`
			} `json:"cvss"`
			Fix struct {
				Versions []string `json:"versions"`
			} `json:"fix"`
		} `json:"vulnerability"`
		RelatedVulnerabilities []struct {
			ID string `json:"id"`
		} `json:"relatedVulnerabilities"`
		Artifact struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			PURL    string `json:"purl"`
		} `json:"artifact"`
	} `json:"matches"`
}

func parseGrype(data []byte) []Finding {
	var report grypeReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil
	}
	target := grypeTarget(report.Source)
	var findings []Finding
	for _, m := range report.Matches {
		f := Finding{
			Target:     target,
			ID:         orDefault(m.Vulnerability.ID, "UNKNOWN"),
			Severity:   strings.ToUpper(orDefault(m.Vulnerability.Severity, "UNKNOWN")),
			CVSSVector: preferredGrypeCVSS(m.Vulnerability.CVSS),
			Pkg:        orDefault(m.Artifact.Name, "?"),
			Installed:  orDefault(m.Artifact.Version, "?"),
			Fixed:      strings.Join(m.Vulnerability.Fix.Versions, ","),
			PURL:       stripPurlVersion(m.Artifact.PURL),
		}
		for _, rv := range m.RelatedVulnerabilities {
			if rv.ID != "" && rv.ID != f.ID {
				f.Aliases = append(f.Aliases, rv.ID)
			}
		}
		findings = append(findings, f)
	}
	return findings
}

func preferredGrypeCVSS(entries []struct {
	Vector string `json:"vector"`
}) string {
	vectors := make([]string, 0, len(entries))
	for _, entry := range entries {
		vectors = append(vectors, entry.Vector)
	}
	return preferredCVSS(vectors)
}

// preferredCVSS selects a GitHub-compatible CVSS v4 vector when available,
// otherwise CVSS v3. Scanner-provided ordering is preserved within a version.
func preferredCVSS(vectors []string) string {
	for _, prefix := range []string{"CVSS:4.", "CVSS:3."} {
		for _, vector := range vectors {
			if strings.HasPrefix(vector, prefix) {
				return vector
			}
		}
	}
	return ""
}

// grypeTarget handles Grype's source.target, which is a string for directory
// scans and an object for image scans.
func grypeTarget(raw json.RawMessage) string {
	var s struct {
		Target json.RawMessage `json:"target"`
	}
	if err := json.Unmarshal(raw, &s); err != nil || s.Target == nil {
		return "unknown"
	}
	var str string
	if err := json.Unmarshal(s.Target, &str); err == nil {
		return str
	}
	var obj struct {
		UserInput string `json:"userInput"`
	}
	if err := json.Unmarshal(s.Target, &obj); err == nil && obj.UserInput != "" {
		return obj.UserInput
	}
	return "unknown"
}

// stripPurlVersion drops the @version segment, leaving e.g.
// "pkg:pypi/werkzeug".
func stripPurlVersion(purl string) string {
	if i := strings.Index(purl, "@"); i >= 0 {
		return purl[:i]
	}
	return purl
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
