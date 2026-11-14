// Package githubadvisory converts Suture remediation plans into the OSV 1.4
// request body accepted by GitHub's enterprise innersource vulnerability API.
package githubadvisory

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

type report struct {
	Recommendations []recommendation `json:"remediation_recommendations"`
}

type recommendation struct {
	ID         string   `json:"id"`
	Aliases    []string `json:"aliases,omitempty"`
	Severity   string   `json:"severity"`
	CVSSVector string   `json:"cvss_vector,omitempty"`
	Installed  string   `json:"installed"`
	FixPURL    string   `json:"fix_purl,omitempty"`
	FixApplied bool     `json:"fix_applied"`
	Action     string   `json:"action"`
}

// Payload is the request body for
// POST /enterprises/{enterprise}/innersource-vulnerabilities/sync.
type Payload struct {
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type Vulnerability struct {
	SchemaVersion    string           `json:"schema_version"`
	ID               string           `json:"id"`
	Modified         string           `json:"modified"`
	Summary          string           `json:"summary"`
	Details          string           `json:"details"`
	Aliases          []string         `json:"aliases,omitempty"`
	Severity         []Severity       `json:"severity"`
	Affected         []Affected       `json:"affected"`
	DatabaseSpecific DatabaseSpecific `json:"database_specific"`
}

type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type Affected struct {
	Package Package `json:"package"`
	Ranges  []Range `json:"ranges"`
}

type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

type Event struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

type DatabaseSpecific struct {
	Severity string `json:"severity"`
}

var ecosystems = map[string]string{
	"npm":    "npm",
	"pypi":   "PyPI",
	"gem":    "RubyGems",
	"maven":  "Maven",
	"nuget":  "NuGet",
	"cargo":  "crates.io",
	"golang": "Go",
}

// Export validates and converts an advisor JSON report. It fails closed when
// a candidate lacks data GitHub requires rather than fabricating an advisory.
func Export(data []byte, modified time.Time) ([]byte, error) {
	var input report
	if err := json.Unmarshal(data, &input); err != nil {
		return nil, fmt.Errorf("parse remediation plan: %w", err)
	}

	byID := map[string]*Vulnerability{}
	var validation []string
	for i, row := range input.Recommendations {
		if row.Action != "backport" || row.FixApplied || row.FixPURL == "" {
			continue
		}
		ecosystem, name, fixed, ok := purlParts(row.FixPURL)
		if !ok {
			validation = append(validation, fmt.Sprintf("row %d (%s): invalid fix_purl %q", i+1, row.ID, row.FixPURL))
			continue
		}
		githubEcosystem, supported := ecosystems[ecosystem]
		if !supported {
			validation = append(validation, fmt.Sprintf("row %d (%s): unsupported GitHub ecosystem %q", i+1, row.ID, ecosystem))
			continue
		}
		cvssType := cvssType(row.CVSSVector)
		if cvssType == "" {
			validation = append(validation, fmt.Sprintf("row %d (%s): scanner did not provide a CVSS v3/v4 vector", i+1, row.ID))
			continue
		}
		if row.Installed == "" || row.Installed == "?" {
			validation = append(validation, fmt.Sprintf("row %d (%s): installed version is required", i+1, row.ID))
			continue
		}

		canonical := canonicalID(row.ID, row.Aliases)
		externalID := externalID(canonical, githubEcosystem, name)
		vuln := byID[externalID]
		if vuln == nil {
			vuln = &Vulnerability{
				SchemaVersion: "1.4.0",
				ID:            externalID,
				Modified:      modified.UTC().Format(time.RFC3339),
				Summary:       fmt.Sprintf("%s in %s", canonical, name),
				Details:       fmt.Sprintf("Suture identified an unapplied supplier backport for %s in %s.", canonical, name),
				Aliases:       cveAliases(row.ID, row.Aliases),
				Severity:      []Severity{{Type: cvssType, Score: row.CVSSVector}},
				DatabaseSpecific: DatabaseSpecific{
					Severity: githubSeverity(row.Severity),
				},
			}
			byID[externalID] = vuln
		}
		vuln.Affected = appendUniqueAffected(vuln.Affected, Affected{
			Package: Package{Ecosystem: githubEcosystem, Name: name},
			Ranges: []Range{{
				Type: "ECOSYSTEM",
				Events: []Event{
					{Introduced: row.Installed},
					{Fixed: fixed},
				},
			}},
		})
	}
	if len(validation) > 0 {
		return nil, fmt.Errorf("cannot export GitHub advisories:\n- %s", strings.Join(validation, "\n- "))
	}
	if len(byID) == 0 {
		return nil, fmt.Errorf("no unapplied backport recommendations to export")
	}
	if len(byID) > 100 {
		return nil, fmt.Errorf("GitHub accepts at most 100 vulnerabilities per sync request; got %d", len(byID))
	}

	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	payload := Payload{Vulnerabilities: make([]Vulnerability, 0, len(ids))}
	for _, id := range ids {
		payload.Vulnerabilities = append(payload.Vulnerabilities, *byID[id])
	}
	return json.MarshalIndent(payload, "", "  ")
}

func purlParts(purl string) (ecosystem, name, version string, ok bool) {
	rest, found := strings.CutPrefix(purl, "pkg:")
	if !found {
		return "", "", "", false
	}
	ecosystem, rest, found = strings.Cut(rest, "/")
	if !found {
		return "", "", "", false
	}
	path, version, found := strings.Cut(rest, "@")
	if !found || path == "" || version == "" {
		return "", "", "", false
	}
	version, _, _ = strings.Cut(version, "?")
	version, _, _ = strings.Cut(version, "#")
	path, pathErr := url.PathUnescape(path)
	version, versionErr := url.PathUnescape(version)
	if pathErr != nil || versionErr != nil {
		return "", "", "", false
	}
	if ecosystem == "maven" {
		group, artifact, found := strings.Cut(path, "/")
		if !found || group == "" || artifact == "" {
			return "", "", "", false
		}
		name = group + ":" + artifact
	} else {
		name = path
	}
	return ecosystem, name, version, true
}

func cvssType(vector string) string {
	switch {
	case strings.HasPrefix(vector, "CVSS:4."):
		return "CVSS_V4"
	case strings.HasPrefix(vector, "CVSS:3."):
		return "CVSS_V3"
	default:
		return ""
	}
}

func canonicalID(id string, aliases []string) string {
	for _, candidate := range append([]string{id}, aliases...) {
		if strings.HasPrefix(strings.ToUpper(candidate), "CVE-") {
			return strings.ToUpper(candidate)
		}
	}
	return id
}

func externalID(vulnerability, ecosystem, name string) string {
	sum := sha256.Sum256([]byte(vulnerability + "\x00" + ecosystem + "\x00" + name))
	return "SUTURE-" + strings.ToUpper(hex.EncodeToString(sum[:8]))
}

func cveAliases(id string, aliases []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, candidate := range append([]string{id}, aliases...) {
		candidate = strings.ToUpper(candidate)
		if strings.HasPrefix(candidate, "CVE-") && !seen[candidate] {
			seen[candidate] = true
			out = append(out, candidate)
		}
	}
	sort.Strings(out)
	return out
}

func githubSeverity(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MEDIUM", "MODERATE":
		return "moderate"
	default:
		return "low"
	}
}

func appendUniqueAffected(existing []Affected, candidate Affected) []Affected {
	candidateJSON, _ := json.Marshal(candidate)
	for _, item := range existing {
		itemJSON, _ := json.Marshal(item)
		if string(itemJSON) == string(candidateJSON) {
			return existing
		}
	}
	return append(existing, candidate)
}
