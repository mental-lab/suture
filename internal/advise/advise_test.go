package advise

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mental-lab/suture/internal/feed"
	"github.com/mental-lab/suture/internal/scan"
)

func TestDecide(t *testing.T) {
	cases := []struct {
		name                            string
		severity                        string
		internetFacing, hasFix, applied bool
		want                            string
	}{
		{"fix already applied", "CRITICAL", true, true, true, "none"},
		{"backport when fix available", "HIGH", true, true, false, "backport"},
		{"backport regardless of exposure", "LOW", false, true, false, "backport"},
		{"upgrade-or-replace for exposed high", "CRITICAL", true, false, false, "upgrade-or-replace"},
		{"exception-review when lower risk", "MEDIUM", false, false, false, "exception-review"},
		{"exception-review for internal high", "HIGH", false, false, false, "exception-review"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			action, _ := Decide(tc.severity, tc.internetFacing, tc.hasFix, tc.applied)
			if action != tc.want {
				t.Errorf("Decide() action = %q, want %q", action, tc.want)
			}
		})
	}
}

func TestChainguardFixesSortsNewestFirst(t *testing.T) {
	doc, err := feed.ParseDocument([]byte(`{
	  "statements": [
	    {"status": "fixed", "vulnerability": {"name": "CVE-1"},
	     "products": [{"identifiers": {"purl": "pkg:pypi/werkzeug@2.2.3%2Bcgr.1"}}]},
	    {"status": "fixed", "vulnerability": {"aliases": ["CVE-1"]},
	     "products": [{"identifiers": {"purl": "pkg:pypi/werkzeug@2.2.3%2Bcgr.2"}}]}
	  ]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	fixes := ChainguardFixes(doc, "CVE-1")
	if len(fixes) != 2 || !strings.Contains(fixes[0], "cgr.2") {
		t.Errorf("fixes = %v, want newest (+cgr.2) first, matched via alias", fixes)
	}
}

func TestSameVersionFirst(t *testing.T) {
	fixes := []string{
		"pkg:pypi/setuptools@77.0.3%2Bcgr.1",
		"pkg:pypi/setuptools@70.1.1%2Bcgr.1",
		"pkg:pypi/setuptools@70.3.0%2Bcgr.1",
	}
	got := SameVersionFirst(fixes, "70.3.0")
	if want := "pkg:pypi/setuptools@70.3.0%2Bcgr.1"; got[0] != want {
		t.Errorf("SameVersionFirst[0] = %s, want same-version backport %s", got[0], want)
	}
	// No same-version fix: order unchanged (newest first as given).
	got = SameVersionFirst(fixes, "68.0.0")
	if got[0] != fixes[0] {
		t.Errorf("SameVersionFirst with no match should preserve order, got %v", got)
	}
	// Already-remediated install still matches its own backport first.
	got = SameVersionFirst(fixes, "70.3.0+cgr.1")
	if got[0] != "pkg:pypi/setuptools@70.3.0%2Bcgr.1" {
		t.Errorf("installed +cgr.1 should match its base version, got %v", got)
	}
}

func TestFixApplied(t *testing.T) {
	fixes := []string{"pkg:pypi/werkzeug@2.2.3%2Bcgr.1"}
	if !fixApplied("2.2.3+cgr.1", fixes) {
		t.Error("installed 2.2.3+cgr.1 should match the %2B-encoded fixed purl")
	}
	if fixApplied("2.2.3", fixes) {
		t.Error("unpatched 2.2.3 must not be reported as applied")
	}
}

func TestSuggestion(t *testing.T) {
	got := Suggestion("pkg:pypi/werkzeug@2.2.3%2Bcgr.1", "pypi")
	want := "werkzeug==2.2.3+cgr.1  (from https://libraries.cgr.dev/python/)"
	if got != want {
		t.Errorf("Suggestion() = %q, want %q", got, want)
	}
}

// fakeFeed serves a minimal OpenVEX feed with one package document.
func fakeFeed(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/all.json":
			fmt.Fprint(w, `{"entries": [{"id": "pypi/werkzeug.openvex.json"}]}`)
		case "/pypi/werkzeug.openvex.json":
			fmt.Fprint(w, `{"statements": [{
			  "status": "fixed",
			  "vulnerability": {"name": "CVE-2023-25577"},
			  "products": [{"identifiers": {"purl": "pkg:pypi/werkzeug@2.2.3%2Bcgr.1"}}]
			}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestAnalyzeAndBlocking(t *testing.T) {
	server := fakeFeed(t)
	defer server.Close()

	client := feed.New()
	client.BaseURL = server.URL
	advisor := New(client, "pypi", true)

	findings := []scan.Finding{
		{Target: "requirements.txt", ID: "CVE-2023-25577", Severity: "HIGH", Pkg: "werkzeug", Installed: "2.2.3"},
		{Target: "requirements.txt", ID: "CVE-2023-25577", Severity: "HIGH", Pkg: "werkzeug", Installed: "2.2.3+cgr.1"},
		{Target: "requirements.txt", ID: "CVE-9999-0000", Severity: "LOW", Pkg: "unknownpkg", Installed: "1.0"},
	}
	rows, err := advisor.Analyze(context.Background(), findings)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("Analyze() returned %d rows, want 3", len(rows))
	}

	unpatched := rows[0]
	if unpatched.Action != "backport" || unpatched.FixApplied {
		t.Errorf("unpatched row = %+v, want action=backport, FixApplied=false", unpatched)
	}
	if !strings.Contains(unpatched.ChainguardFix, "werkzeug==2.2.3+cgr.1") {
		t.Errorf("ChainguardFix = %q, want the +cgr.1 suggestion", unpatched.ChainguardFix)
	}

	patched := rows[1]
	if patched.Action != "none" || !patched.FixApplied {
		t.Errorf("patched row = %+v, want action=none, FixApplied=true", patched)
	}

	if rows[2].Action != "exception-review" {
		t.Errorf("unknown package row action = %q, want exception-review", rows[2].Action)
	}

	blocking := Blocking(rows)
	if len(blocking) != 1 || blocking[0].Installed != "2.2.3" {
		t.Errorf("Blocking() = %v, want exactly the unpatched row", blocking)
	}
}

// Grype reports the GHSA as primary with the CVE in relatedVulnerabilities,
// and carries the artifact purl. The lookup must match via the alias and
// resolve the feed entry from the purl, not the --index-prefix flag.
func TestAnalyzeGrypeStyleFinding(t *testing.T) {
	server := fakeFeed(t)
	defer server.Close()

	client := feed.New()
	client.BaseURL = server.URL
	advisor := New(client, "unused-prefix", false)

	findings := []scan.Finding{{
		Target:    "myapp:latest",
		ID:        "GHSA-xrfv-9qxx-8jxp",
		Severity:  "HIGH",
		Pkg:       "werkzeug",
		Installed: "2.2.3",
		PURL:      "pkg:pypi/werkzeug",
		Aliases:   []string{"CVE-2023-25577"},
	}}
	rows, err := advisor.Analyze(context.Background(), findings)
	if err != nil {
		t.Fatal(err)
	}
	if rows[0].Action != "backport" {
		t.Errorf("action = %q, want backport via alias match", rows[0].Action)
	}
	if !strings.Contains(rows[0].ChainguardFix, "werkzeug==2.2.3+cgr.1") {
		t.Errorf("ChainguardFix = %q, want the pypi suggestion from the purl ecosystem", rows[0].ChainguardFix)
	}
}

func TestEntryIDFor(t *testing.T) {
	withPurl := entryIDFor(scan.Finding{Pkg: "h2", PURL: "pkg:maven/com.h2database/h2"}, "pypi")
	if withPurl != "maven/com.h2database/h2.openvex.json" {
		t.Errorf("entryIDFor() = %q, want purl-derived entry", withPurl)
	}
	noPurl := entryIDFor(scan.Finding{Pkg: "werkzeug"}, "pypi")
	if noPurl != "pypi/werkzeug.openvex.json" {
		t.Errorf("entryIDFor() = %q, want prefix/pkg fallback", noPurl)
	}
}

func TestMarkdown(t *testing.T) {
	rows := []Row{
		{
			Finding:        scan.Finding{ID: "CVE-1", Severity: "HIGH", Pkg: "werkzeug", Installed: "2.2.3"},
			InternetFacing: true,
			ChainguardFix:  "werkzeug==2.2.3+cgr.1",
			Action:         "backport",
			Rationale:      "fix exists",
		},
		{
			Finding:        scan.Finding{ID: "CVE-2", Severity: "LOW", Pkg: "idna", Installed: "3.13"},
			InternetFacing: true,
			Action:         "exception-review",
			Rationale:      "lower risk",
		},
		{
			Finding:        scan.Finding{ID: "GHSA-3", Severity: "HIGH", Pkg: "msgpack", Installed: "1.1.2", Fixed: "1.2.1"},
			InternetFacing: true,
			Action:         "upgrade-or-replace",
			Rationale:      "no backport",
		},
	}
	md := Markdown(rows)
	for _, want := range []string{"CVE-1", "werkzeug==2.2.3+cgr.1", "**backport**", "fix exists",
		"**3 findings**", "🔧 1 with a Chainguard fix", "Action required", "<details>",
		"msgpack==1.2.1 (upstream)", "Upstream fixed in msgpack==1.2.1."} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
	// Non-actionable rows belong in the collapsed section only.
	actionSection := md[:strings.Index(md, "<details>")]
	if strings.Contains(actionSection, "CVE-2") {
		t.Error("exception-review row leaked into the action-required section")
	}
}

func TestLibrariesScope(t *testing.T) {
	findings := []scan.Finding{
		{ID: "CVE-1", Pkg: "werkzeug", PURL: "pkg:pypi/werkzeug"},
		{ID: "CVE-2", Pkg: "log4j-core", PURL: "pkg:maven/org.apache.logging.log4j/log4j-core"},
		{ID: "GHSA-3", Pkg: "actions/download-artifact", PURL: "pkg:github/actions/download-artifact@v4"},
		{ID: "CVE-4", Pkg: "node", PURL: "pkg:generic/node@22.18.0"},
		{ID: "CVE-5", Pkg: "flask"}, // no purl (Trivy) — kept
	}
	kept, dropped := LibrariesScope(findings)
	if len(kept) != 3 || len(dropped) != 2 {
		t.Errorf("kept=%d dropped=%d, want 3/2", len(kept), len(dropped))
	}
	for _, f := range dropped {
		if f.PURL == "" || LibrariesEcosystems[strings.Split(strings.TrimPrefix(f.PURL, "pkg:"), "/")[0]] {
			t.Errorf("dropped finding %v should be outside Libraries ecosystems", f.ID)
		}
	}
}

func TestDedupeRows(t *testing.T) {
	row := Row{Finding: scan.Finding{ID: "CVE-1", Pkg: "werkzeug", Installed: "2.2.3"}, Action: "backport"}
	rows := dedupeRows([]Row{row, row, row})
	if len(rows) != 1 {
		t.Errorf("dedupeRows kept %d of 3 identical rows", len(rows))
	}
}
