package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/mental-lab/suture/internal/manifest"
	"github.com/spf13/cobra"
)

var (
	fixFrom   string
	fixDir    string
	fixWrite  bool
	fixFormat string
	fixOut    string
)

// advisorReport mirrors the advisor's JSON output (suture advise --format json).
// Automation reads the structured fix_purl; chainguard_fix is a display
// string for humans and is never parsed.
type advisorReport struct {
	Recommendations []struct {
		ID        string `json:"id"`
		Pkg       string `json:"pkg"`
		Installed string `json:"installed"`
		Action    string `json:"action"`
		FixPURL   string `json:"fix_purl,omitempty"`
	} `json:"remediation_recommendations"`
}

// fixChange is one applied backport, for the summary/PR body.
type fixChange struct {
	File      string   `json:"file"`
	Ecosystem string   `json:"ecosystem"`
	Package   string   `json:"package"`
	From      string   `json:"from"`
	To        string   `json:"to"`
	Addresses []string `json:"addresses"`
}

var fixCmd = &cobra.Command{
	Use:   "fix",
	Short: "Apply Chainguard backports recommended by the advisor to dependency manifests",
	Long: `Dependabot-style backport application. Consumes the advisor's JSON output
(suture advise --format json), takes every row with action="backport", and
rewrites the corresponding pins in the dependency manifests discovered
under --dir (requirements*.txt, package.json, pom.xml — the Chainguard
Libraries ecosystems).

Backports are same-version (<version>+cgr.N) — non-breaking by construction.
A pin is only rewritten when it still matches the scanned version, so the
command is idempotent and never touches a pin that has already moved.
Findings needing an upstream upgrade or exception review are left to the
advisor report.

Pair with a scheduled workflow and a PR-creation action (e.g.
peter-evans/create-pull-request) for automated backport PRs:

  suture advise --scan-dir results/ --format json --out vex-report.json
  suture fix --from vex-report.json --write --out summary.md`,
	Example: `  suture advise --format json --scan-dir results/ | suture fix        # dry run
  suture fix --from vex-report.json --write                          # apply pins
  suture fix --from vex-report.json --write --format json --out changes.json`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		var data []byte
		var err error
		if fixFrom == "" || fixFrom == "-" {
			data, err = io.ReadAll(cmd.InOrStdin())
		} else {
			data, err = os.ReadFile(fixFrom)
		}
		if err != nil {
			return fmt.Errorf("read advisor report: %w", err)
		}
		var report advisorReport
		if err := json.Unmarshal(data, &report); err != nil {
			return fmt.Errorf("parse advisor report: %w", err)
		}

		// Collect backport pins per ecosystem: ecosystem → name → update,
		// plus the vuln IDs each backport addresses. Names use the
		// ecosystem's manifest naming (pypi: lowercase, npm: scoped name,
		// maven: group:artifact).
		type update struct {
			u         manifest.Update
			addresses []string
		}
		updates := map[string]map[string]update{}
		for _, r := range report.Recommendations {
			if r.Action != "backport" || r.FixPURL == "" {
				continue
			}
			eco, name, version, ok := purlParts(r.FixPURL)
			if !ok {
				fmt.Fprintf(cmd.ErrOrStderr(), "warn: %s: unparsable fix_purl %q\n", r.ID, r.FixPURL)
				continue
			}
			if eco == "pypi" {
				name = strings.ToLower(name)
			}
			if updates[eco] == nil {
				updates[eco] = map[string]update{}
			}
			u := updates[eco][name]
			u.u = manifest.Update{From: r.Installed, To: version}
			u.addresses = append(u.addresses, r.ID)
			updates[eco][name] = u
		}

		// Discover manifests and apply each ecosystem's pins via its patcher.
		manifests, err := manifest.Discover(fixDir)
		if err != nil {
			return err
		}
		changes := []fixChange{}
		for _, path := range manifests {
			p := manifest.PatcherFor(path)
			if p == nil {
				continue
			}
			ecoUpdates := updates[p.Name]
			if len(ecoUpdates) == 0 {
				continue
			}
			content, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("read %s: %w", path, err)
			}
			pins := map[string]manifest.Update{}
			for name, u := range ecoUpdates {
				pins[name] = u.u
			}
			rewritten, applied := p.Rewrite(string(content), pins)
			if len(applied) == 0 {
				continue
			}
			if fixWrite {
				if err := os.WriteFile(path, []byte(rewritten), 0o644); err != nil {
					return fmt.Errorf("write %s: %w", path, err)
				}
			}
			rel, _ := filepath.Rel(fixDir, path)
			for _, a := range applied {
				changes = append(changes, fixChange{
					File:      rel,
					Ecosystem: p.Name,
					Package:   a.Name,
					From:      a.From,
					To:        a.To,
					Addresses: ecoUpdates[a.Name].addresses,
				})
			}
		}

		var out string
		switch fixFormat {
		case "markdown":
			out = fixMarkdown(changes, fixWrite)
		case "json":
			b, err := json.MarshalIndent(map[string]any{"changes": changes}, "", "  ")
			if err != nil {
				return err
			}
			out = string(b) + "\n"
		default:
			return fmt.Errorf("unknown --format %q (markdown|json)", fixFormat)
		}
		if fixOut != "" {
			return os.WriteFile(fixOut, []byte(out), 0o644)
		}
		fmt.Fprint(cmd.OutOrStdout(), out)
		return nil
	},
}

// purlParts decomposes a package-url into ecosystem, manifest-facing name,
// and version. Feed purls url-encode the +cgr.N local segment as %2B.
//
//	pkg:pypi/werkzeug@2.2.3%2Bcgr.1              → pypi, werkzeug, 2.2.3+cgr.1
//	pkg:maven/org.apache/commons-lang3@3.12.0+cgr.1 → maven, org.apache:commons-lang3, 3.12.0+cgr.1
//	pkg:npm/%40scope/pkg@1.0.0%2Bcgr.1           → npm, @scope/pkg, 1.0.0+cgr.1
func purlParts(purl string) (eco, name, version string, ok bool) {
	rest, found := strings.CutPrefix(purl, "pkg:")
	if !found {
		return "", "", "", false
	}
	eco, rest, found = strings.Cut(rest, "/")
	if !found {
		return "", "", "", false
	}
	path, version, found := strings.Cut(rest, "@")
	if !found || version == "" {
		return "", "", "", false
	}
	if v, err := url.PathUnescape(version); err == nil {
		version = v
	}
	if p, err := url.PathUnescape(path); err == nil {
		path = p
	}
	switch eco {
	case "maven":
		group, artifact, found := strings.Cut(path, "/")
		if !found {
			return "", "", "", false
		}
		name = group + ":" + artifact
	default:
		name = path
	}
	return eco, name, version, true
}

func fixMarkdown(changes []fixChange, applied bool) string {
	var b strings.Builder
	b.WriteString("## Chainguard backports\n\n")
	if len(changes) == 0 {
		b.WriteString("No same-version backports to apply — nothing actionable in the advisor report.\n")
		return b.String()
	}
	verb := "have a backport available (dry run — pass --write to apply)"
	if applied {
		verb = "updated to Chainguard-patched builds"
	}
	fmt.Fprintf(&b, "**%d pin(s) %s:**\n\n", len(changes), verb)
	b.WriteString("| File | Package | From | To | Addresses |\n| --- | --- | --- | --- | --- |\n")
	for _, c := range changes {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n",
			c.File, c.Package, c.From, c.To, strings.Join(c.Addresses, ", "))
	}
	b.WriteString("\nSame-version backports are non-breaking; the existing test suite validates the change.\n")
	return b.String()
}

func init() {
	fixCmd.Flags().StringVar(&fixFrom, "from", "-", "advisor JSON report to read (path, or - for stdin)")
	fixCmd.Flags().StringVar(&fixDir, "dir", ".", "repository root to scan for manifests")
	fixCmd.Flags().BoolVar(&fixWrite, "write", false, "rewrite manifests in place (default: dry run)")
	fixCmd.Flags().StringVar(&fixFormat, "format", "markdown", "summary format: markdown|json")
	fixCmd.Flags().StringVar(&fixOut, "out", "", "write the summary to a file instead of stdout")
	rootCmd.AddCommand(fixCmd)
}
