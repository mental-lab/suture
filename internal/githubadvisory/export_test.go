package githubadvisory

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const cvss = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

func TestExport(t *testing.T) {
	input := `{
  "remediation_recommendations": [
    {
      "id": "GHSA-xrfv-9qxx-8jxp",
      "aliases": ["CVE-2023-25577"],
      "severity": "HIGH",
      "cvss_vector": "` + cvss + `",
      "pkg": "werkzeug",
      "installed": "2.2.3",
      "fix_purl": "pkg:pypi/werkzeug@2.2.3%2Bcgr.1",
      "fix_applied": false,
      "action": "backport"
    }
  ]
}`
	modified := time.Date(2026, 11, 14, 20, 0, 0, 0, time.UTC)
	data, err := Export([]byte(input), modified)
	if err != nil {
		t.Fatal(err)
	}
	var payload Payload
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Vulnerabilities) != 1 {
		t.Fatalf("vulnerabilities = %d, want 1", len(payload.Vulnerabilities))
	}
	v := payload.Vulnerabilities[0]
	if v.SchemaVersion != "1.4.0" || v.Modified != "2026-11-14T20:00:00Z" {
		t.Errorf("schema/modified = %q/%q", v.SchemaVersion, v.Modified)
	}
	if len(v.Aliases) != 1 || v.Aliases[0] != "CVE-2023-25577" {
		t.Errorf("aliases = %v", v.Aliases)
	}
	if len(v.Severity) != 1 || v.Severity[0].Type != "CVSS_V3" || v.Severity[0].Score != cvss {
		t.Errorf("severity = %+v", v.Severity)
	}
	affected := v.Affected[0]
	if affected.Package.Ecosystem != "PyPI" || affected.Package.Name != "werkzeug" {
		t.Errorf("package = %+v", affected.Package)
	}
	events := affected.Ranges[0].Events
	if events[0].Introduced != "2.2.3" || events[1].Fixed != "2.2.3+cgr.1" {
		t.Errorf("events = %+v", events)
	}
}

func TestExportFailsWithoutRequiredCVSS(t *testing.T) {
	input := `{"remediation_recommendations":[{
    "id":"CVE-2023-25577","severity":"HIGH","installed":"2.2.3",
    "fix_purl":"pkg:pypi/werkzeug@2.2.3%2Bcgr.1","action":"backport"
  }]}`
	_, err := Export([]byte(input), time.Now())
	if err == nil || !strings.Contains(err.Error(), "scanner did not provide a CVSS v3/v4 vector") {
		t.Fatalf("Export() error = %v", err)
	}
}

func TestExportSkipsNonBackportsAndAppliedFixes(t *testing.T) {
	input := `{"remediation_recommendations":[
    {"id":"CVE-1","action":"upgrade"},
    {"id":"CVE-2","action":"backport","fix_applied":true,"fix_purl":"pkg:pypi/x@1.0%2Bcgr.1"}
  ]}`
	_, err := Export([]byte(input), time.Now())
	if err == nil || !strings.Contains(err.Error(), "no unapplied backport recommendations") {
		t.Fatalf("Export() error = %v", err)
	}
}

func TestExportAggregatesAffectedRanges(t *testing.T) {
	input := `{"remediation_recommendations":[
    {"id":"CVE-2026-1","severity":"HIGH","cvss_vector":"` + cvss + `","installed":"1.0","fix_purl":"pkg:npm/example@1.0.0%2Bcgr.1","action":"backport"},
    {"id":"CVE-2026-1","severity":"HIGH","cvss_vector":"` + cvss + `","installed":"1.0","fix_purl":"pkg:npm/example@1.0.0%2Bcgr.1","action":"backport"}
  ]}`
	data, err := Export([]byte(input), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var payload Payload
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Vulnerabilities) != 1 || len(payload.Vulnerabilities[0].Affected) != 1 {
		t.Fatalf("payload = %+v", payload)
	}
}

func TestPURLPartsDropsQualifiers(t *testing.T) {
	ecosystem, name, version, ok := purlParts("pkg:maven/org.example/demo@1.2.3-0.cgr.1?repository_url=https%3A%2F%2Fexample.invalid")
	if !ok || ecosystem != "maven" || name != "org.example:demo" || version != "1.2.3-0.cgr.1" {
		t.Fatalf("purlParts() = %q, %q, %q, %v", ecosystem, name, version, ok)
	}
}
