package scan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDirTrivy(t *testing.T) {
	dir := t.TempDir()
	report := `{
	  "Results": [{
	    "Target": "requirements.txt",
	    "Vulnerabilities": [{
	      "VulnerabilityID": "CVE-2023-25577",
	      "Severity": "high",
	      "CVSS": {"nvd": {"V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
	      "PkgName": "werkzeug",
	      "InstalledVersion": "2.2.3",
	      "FixedVersion": "2.3.8"
	    }]
	  }]
	}`
	if err := os.WriteFile(filepath.Join(dir, "fs-scan.json"), []byte(report), 0o644); err != nil {
		t.Fatal(err)
	}
	// Files that do not parse are skipped, not fatal.
	if err := os.WriteFile(filepath.Join(dir, "not-json.json"), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}

	findings, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("LoadDir() = %d findings, want 1", len(findings))
	}
	f := findings[0]
	if f.ID != "CVE-2023-25577" || f.Severity != "HIGH" || f.Pkg != "werkzeug" || f.Installed != "2.2.3" || f.Fixed != "2.3.8" {
		t.Errorf("unexpected finding: %+v", f)
	}
	if f.CVSSVector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" {
		t.Errorf("CVSSVector = %q, want scanner-provided CVSS v3 vector", f.CVSSVector)
	}
}

func TestLoadDirTrivyPopulatesPURL(t *testing.T) {
	// Trivy findings carry only CVE IDs; without the purl the advisor cannot
	// key the finding to the feed cache and silently finds zero fixes.
	dir := t.TempDir()
	report := `{
	  "Results": [{
	    "Target": "Python",
	    "Class": "lang-pkgs",
	    "Vulnerabilities": [{
	      "VulnerabilityID": "CVE-2023-25577",
	      "Severity": "HIGH",
	      "PkgName": "werkzeug",
	      "InstalledVersion": "2.2.3",
	      "PkgIdentifier": {"PURL": "pkg:pypi/werkzeug@2.2.3"}
	    }]
	  }]
	}`
	if err := os.WriteFile(filepath.Join(dir, "image-scan.json"), []byte(report), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("LoadDir() = %d findings, want 1", len(findings))
	}
	if findings[0].PURL != "pkg:pypi/werkzeug" {
		t.Errorf("PURL = %q, want version-less purl", findings[0].PURL)
	}
}

func TestLoadDirTrivySkipsOSPackages(t *testing.T) {
	dir := t.TempDir()
	report := `{
	  "Results": [
	    {"Target": "python:3.12-slim (debian 13.1)", "Class": "os-pkgs",
	     "Vulnerabilities": [{"VulnerabilityID": "CVE-2010-4756", "Severity": "LOW",
	       "PkgName": "libc6", "InstalledVersion": "2.41-12"}]},
	    {"Target": "Python", "Class": "lang-pkgs",
	     "Vulnerabilities": [{"VulnerabilityID": "CVE-2023-25577", "Severity": "HIGH",
	       "PkgName": "werkzeug", "InstalledVersion": "2.2.3"}]}
	  ]
	}`
	if err := os.WriteFile(filepath.Join(dir, "image-scan.json"), []byte(report), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Pkg != "werkzeug" {
		t.Fatalf("os-pkgs should be dropped, lang-pkgs kept; got %+v", findings)
	}
}

func TestLoadDirGrype(t *testing.T) {
	dir := t.TempDir()
	// Grype image scan: GHSA-primary ID, CVE in relatedVulnerabilities,
	// object-valued source.target, fix versions, artifact purl.
	report := `{
	  "source": {"type": "image", "target": {"userInput": "myapp:latest"}},
	  "matches": [{
	    "vulnerability": {
	      "id": "GHSA-xrfv-9qxx-8jxp",
	      "severity": "High",
	      "cvss": [{"version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
	      "fix": {"versions": ["2.3.8", "3.0.1"]}
	    },
	    "relatedVulnerabilities": [{"id": "CVE-2023-25577"}],
	    "artifact": {
	      "name": "werkzeug",
	      "version": "2.2.3",
	      "type": "python",
	      "purl": "pkg:pypi/werkzeug@2.2.3"
	    }
	  }]
	}`
	if err := os.WriteFile(filepath.Join(dir, "grype.json"), []byte(report), 0o644); err != nil {
		t.Fatal(err)
	}

	findings, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("LoadDir() = %d findings, want 1", len(findings))
	}
	f := findings[0]
	if f.ID != "GHSA-xrfv-9qxx-8jxp" || f.Severity != "HIGH" || f.Pkg != "werkzeug" || f.Installed != "2.2.3" {
		t.Errorf("unexpected finding: %+v", f)
	}
	if f.Target != "myapp:latest" {
		t.Errorf("Target = %q, want image userInput", f.Target)
	}
	if f.PURL != "pkg:pypi/werkzeug" {
		t.Errorf("PURL = %q, want version-less purl", f.PURL)
	}
	if f.Fixed != "2.3.8,3.0.1" {
		t.Errorf("Fixed = %q, want joined fix versions", f.Fixed)
	}
	if len(f.Aliases) != 1 || f.Aliases[0] != "CVE-2023-25577" {
		t.Errorf("Aliases = %v, want the related CVE", f.Aliases)
	}
	if f.CVSSVector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" {
		t.Errorf("CVSSVector = %q, want scanner-provided CVSS v3 vector", f.CVSSVector)
	}
}

func TestPreferredCVSSPrefersV4AndIgnoresUnsupported(t *testing.T) {
	got := preferredCVSS([]string{
		"CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
	})
	want := "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
	if got != want {
		t.Fatalf("preferredCVSS() = %q, want %q", got, want)
	}
}

func TestLoadDirEmpty(t *testing.T) {
	findings, err := LoadDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("LoadDir() = %v, want none", findings)
	}
}
