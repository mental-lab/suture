// Package advise cross-references scanner findings against the Chainguard
// Libraries OpenVEX feed and recommends a remediation path per finding:
// same-version backport, upstream upgrade/replacement, or exception review.
package advise

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/mental-lab/suture/internal/feed"
	"github.com/mental-lab/suture/internal/scan"
)

type Row struct {
	scan.Finding
	InternetFacing bool   `json:"internet_facing"`
	ChainguardFix  string `json:"chainguard_fix,omitempty"`
	FixApplied     bool   `json:"fix_applied"`
	Action         string `json:"action"`
	Rationale      string `json:"rationale"`
}

// Advisor looks findings up in the OpenVEX feed, fetching each per-package
// document at most once.
type Advisor struct {
	Feed           *feed.Client
	IndexPrefix    string // feed entry prefix, e.g. "pypi"
	InternetFacing bool
	// Warnf receives per-package fetch warnings; defaults to stderr.
	Warnf func(format string, args ...any)

	index map[string]bool
	docs  map[string]*feed.Document
}

func New(client *feed.Client, indexPrefix string, internetFacing bool) *Advisor {
	return &Advisor{
		Feed:           client,
		IndexPrefix:    indexPrefix,
		InternetFacing: internetFacing,
		Warnf: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "warn: "+format+"\n", args...)
		},
		index: map[string]bool{},
		docs:  map[string]*feed.Document{},
	}
}

func (a *Advisor) Analyze(ctx context.Context, findings []scan.Finding) ([]Row, error) {
	rows := make([]Row, 0, len(findings))
	for _, f := range findings {
		fixes, err := a.fixes(ctx, f)
		if err != nil {
			return nil, err
		}
		row := Row{Finding: f, InternetFacing: a.InternetFacing}
		if len(fixes) > 0 {
			row.ChainguardFix = Suggestion(fixes[0], prefixOf(f, a.IndexPrefix))
			row.FixApplied = fixApplied(f.Installed, fixes)
		}
		row.Action, row.Rationale = Decide(f.Severity, a.InternetFacing, len(fixes) > 0, row.FixApplied)
		rows = append(rows, row)
	}
	return rows, nil
}

// fixes returns the Chainguard-fixed purls for a finding, newest first. The
// lookup matches on any of the finding's identifiers (Grype reports a GHSA
// primary with CVE aliases; Trivy reports the CVE).
func (a *Advisor) fixes(ctx context.Context, f scan.Finding) ([]string, error) {
	doc, err := a.doc(ctx, f)
	if err != nil || doc == nil {
		return nil, err
	}
	return ChainguardFixes(doc, f.IDs()...), nil
}

// doc fetches (and caches) the per-package OpenVEX document. A nil document
// means Chainguard publishes no VEX data for the package, i.e. there is no
// backport coverage to offer.
func (a *Advisor) doc(ctx context.Context, f scan.Finding) (*feed.Document, error) {
	entryID := entryIDFor(f, a.IndexPrefix)
	if doc, ok := a.docs[entryID]; ok {
		return doc, nil
	}
	if !a.feedIndex(ctx)[entryID] {
		a.docs[entryID] = nil
		return nil, nil
	}
	raw, err := a.Feed.FetchRaw(ctx, entryID)
	if err != nil {
		a.Warnf("%s: %v", entryID, err)
		a.docs[entryID] = nil
		return nil, nil
	}
	doc, err := feed.ParseDocument(raw)
	if err != nil {
		a.Warnf("%s: %v", entryID, err)
		a.docs[entryID] = nil
		return nil, nil
	}
	a.docs[entryID] = doc
	return doc, nil
}

// entryIDFor derives the feed entry ID from the finding's purl when present
// (Grype), e.g. "pkg:maven/com.h2database/h2" → "maven/com.h2database/h2.openvex.json",
// falling back to "<index-prefix>/<pkg>.openvex.json" (Trivy).
func entryIDFor(f scan.Finding, defaultPrefix string) string {
	if rest, ok := strings.CutPrefix(f.PURL, "pkg:"); ok {
		return rest + ".openvex.json"
	}
	return fmt.Sprintf("%s/%s.openvex.json", defaultPrefix, f.Pkg)
}

// prefixOf derives the feed ecosystem from the finding's purl when present
// (Grype), falling back to the advisor's --index-prefix (Trivy).
func prefixOf(f scan.Finding, def string) string {
	if rest, ok := strings.CutPrefix(f.PURL, "pkg:"); ok {
		if i := strings.Index(rest, "/"); i > 0 {
			return rest[:i]
		}
	}
	return def
}

func (a *Advisor) feedIndex(ctx context.Context) map[string]bool {
	if len(a.index) == 0 {
		ids, err := a.Feed.Index(ctx)
		if err != nil {
			a.Warnf("feed index: %v", err)
			return a.index
		}
		for _, id := range ids {
			a.index[id] = true
		}
	}
	return a.index
}

// ChainguardFixes returns the fixed purls whose statement matches any of
// the finding's identifiers (by statement name or alias), sorted newest
// version first.
func ChainguardFixes(doc *feed.Document, vulnIDs ...string) []string {
	var fixes []string
	for _, stmt := range doc.Statements {
		if stmt.Status != "fixed" {
			continue
		}
		ids := append([]string{stmt.Vulnerability.Name}, stmt.Vulnerability.Aliases...)
		matched := false
		for _, id := range ids {
			for _, vid := range vulnIDs {
				if id == vid {
					matched = true
					break
				}
			}
		}
		if !matched {
			continue
		}
		for _, p := range stmt.Products {
			if p.Identifiers.PURL != "" {
				fixes = append(fixes, p.Identifiers.PURL)
			}
		}
	}
	sort.SliceStable(fixes, func(i, j int) bool {
		return compareVersions(versionTuple(VersionOf(fixes[i])), versionTuple(VersionOf(fixes[j]))) > 0
	})
	return fixes
}

// Suggestion renders a fixed purl as a human-readable remediation, e.g.
// "werkzeug==2.2.3+cgr.1  (from https://libraries.cgr.dev/python/)".
func Suggestion(purl, indexPrefix string) string {
	version := strings.ReplaceAll(purl[strings.LastIndex(purl, "@")+1:], "%2B", "+")
	name := purl[strings.LastIndex(purl, "/")+1:]
	name = name[:strings.Index(name, "@")]
	if indexPrefix == "pypi" {
		return fmt.Sprintf("%s==%s  (from https://libraries.cgr.dev/python/)", name, version)
	}
	return purl
}

// fixApplied reports whether the installed version is already one of the
// Chainguard-fixed versions — i.e. the backport has been applied.
func fixApplied(installed string, fixes []string) bool {
	for _, fix := range fixes {
		if installed == VersionOf(fix) {
			return true
		}
	}
	return false
}

// VersionOf extracts the version portion of a purl, decoding the OpenVEX
// url-encoded local segment ("2.2.3%2Bcgr.1" → "2.2.3+cgr.1").
func VersionOf(purl string) string {
	return strings.ReplaceAll(purl[strings.LastIndex(purl, "@")+1:], "%2B", "+")
}

func deniedSeverity(severity string) bool {
	return severity == "CRITICAL" || severity == "HIGH"
}

// Decide is the decision framework, mechanized.
func Decide(severity string, internetFacing, hasFix, applied bool) (action, rationale string) {
	switch {
	case hasFix && applied:
		return "none",
			"Chainguard backport already applied — the installed version matches " +
				"a fixed release in the feed."
	case hasFix:
		return "backport",
			"Chainguard-built patched package exists (VEX status=fixed). Backport " +
				"remediates without a breaking upstream upgrade; the same test " +
				"suite must pass on both sides of the change."
	case deniedSeverity(severity) && internetFacing:
		return "upgrade-or-replace",
			"No Chainguard backport coverage in the VEX feed. Internet-facing " +
				severity + ": pursue compatible upstream upgrade; if breaking, " +
				"evaluate package replacement before a compensating control."
	default:
		return "exception-review",
			"No backport available and risk context is lower. A time-boxed " +
				"compensating-control exception may be acceptable."
	}
}

// Blocking returns the rows that fail the gate: internet-facing Critical/High
// findings with a Chainguard fix available but not applied.
func Blocking(rows []Row) []Row {
	var out []Row
	for _, r := range rows {
		if r.InternetFacing && deniedSeverity(r.Severity) && r.ChainguardFix != "" && !r.FixApplied {
			out = append(out, r)
		}
	}
	return out
}

var severityRank = map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

// LibrariesEcosystems are the purl types the Chainguard Libraries OpenVEX
// feed serves. Findings outside this set (e.g. pkg:github actions Grype
// catalogs from workflow files) can never have a Chainguard backport and
// only add noise to the report.
var LibrariesEcosystems = map[string]bool{
	"pypi": true, "maven": true, "npm": true, "gem": true,
	"nuget": true, "cargo": true, "golang": true,
}

// LibrariesScope splits findings into those a Chainguard Libraries fix could
// address (kept) and everything else (dropped). Findings without a purl
// (Trivy output) are kept — their ecosystem comes from --index-prefix.
func LibrariesScope(findings []scan.Finding) (kept, dropped []scan.Finding) {
	for _, f := range findings {
		eco, _, _ := strings.Cut(strings.TrimPrefix(f.PURL, "pkg:"), "/")
		if f.PURL == "" || LibrariesEcosystems[eco] {
			kept = append(kept, f)
		} else {
			dropped = append(dropped, f)
		}
	}
	return kept, dropped
}

// actionable reports whether a row belongs in the top "action required"
// section: a Chainguard fix is waiting, or an exposed Critical/High needs
// an upstream upgrade.
func actionable(r Row) bool {
	return r.Action == "backport" || r.Action == "upgrade-or-replace"
}

// dedupeRows collapses identical findings (same ID, package, version,
// action) that scanners report more than once across targets.
func dedupeRows(rows []Row) []Row {
	seen := map[string]bool{}
	out := make([]Row, 0, len(rows))
	for _, r := range rows {
		key := r.ID + "|" + r.Pkg + "|" + r.Installed + "|" + r.Action
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, r)
	}
	return out
}

func sortRows(rows []Row) {
	sort.SliceStable(rows, func(i, j int) bool {
		ai, aj := actionable(rows[i]), actionable(rows[j])
		if ai != aj {
			return ai
		}
		si, sj := severityRank[rows[i].Severity], severityRank[rows[j].Severity]
		if si != sj {
			return si < sj
		}
		if rows[i].Pkg != rows[j].Pkg {
			return rows[i].Pkg < rows[j].Pkg
		}
		return rows[i].ID < rows[j].ID
	})
}

func Markdown(rows []Row) string {
	rows = dedupeRows(rows)
	sortRows(rows)

	counts := map[string]int{}
	for _, r := range rows {
		counts[r.Action]++
	}

	var b strings.Builder
	b.WriteString("## 🛡️ Remediation Advisor — Chainguard OpenVEX analysis\n\n")
	fmt.Fprintf(&b, "**%d findings** — 🔧 %d with a Chainguard fix ready · ⬆️ %d need an upstream upgrade · 📋 %d exception-review · ✅ %d already fixed\n\n",
		len(rows), counts["backport"], counts["upgrade-or-replace"], counts["exception-review"], counts["none"])

	writeTable := func(rs []Row) {
		b.WriteString("| CVE | Severity | Package | Chainguard fix | Action |\n")
		b.WriteString("| --- | --- | --- | --- | --- |\n")
		for _, r := range rs {
			fix := r.ChainguardFix
			if fix == "" {
				fix = "—"
			}
			fmt.Fprintf(&b, "| %s | %s | `%s %s` | %s | **%s** |\n",
				r.ID, r.Severity, r.Pkg, r.Installed, fix, r.Action)
		}
	}

	var todo, rest []Row
	for _, r := range rows {
		if actionable(r) {
			todo = append(todo, r)
		} else {
			rest = append(rest, r)
		}
	}

	if len(todo) > 0 {
		b.WriteString("### Action required\n\n")
		writeTable(todo)
		b.WriteString("\n### Rationale\n\n")
		for _, r := range todo {
			fmt.Fprintf(&b, "- **%s** (`%s`): %s\n", r.ID, r.Pkg, r.Rationale)
		}
		b.WriteString("\n")
	} else {
		b.WriteString("**No immediate action required** — no Chainguard fix is waiting and no exposed Critical/High needs an upgrade.\n\n")
	}

	if len(rest) > 0 {
		fmt.Fprintf(&b, "<details><summary>All remaining findings (%d) — exception-review and already fixed</summary>\n\n", len(rest))
		writeTable(rest)
		b.WriteString("\n</details>\n")
	}

	b.WriteString("\n> Decision framework: fix available → compatible upgrade → backport → " +
		"replacement → compensating control, weighted by severity × " +
		"exploitability × internet exposure × asset criticality.\n")
	return b.String()
}

func JSON(rows []Row) ([]byte, error) {
	return json.MarshalIndent(struct {
		Recommendations []Row `json:"remediation_recommendations"`
	}{Recommendations: rows}, "", "  ")
}

var digits = regexp.MustCompile(`\d+`)

// versionTuple extracts up to four numeric components from a version string.
func versionTuple(v string) []int {
	parts := digits.FindAllString(v, 4)
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		if n, err := strconv.Atoi(p); err == nil {
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return []int{0}
	}
	return out
}

func compareVersions(a, b []int) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}
