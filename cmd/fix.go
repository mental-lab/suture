package cmd

import (
	"encoding/json"
	"fmt"
	"io"
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
type advisorReport struct {
	Recommendations []struct {
		ID            string `json:"id"`
		Pkg           string `json:"pkg"`
		Installed     string `json:"installed"`
		Action        string `json:"action"`
		ChainguardFix string `json:"chainguard_fix,omitempty"`
	} `json:"remediation_recommendations"`
}

// fixChange is one applied backport, for the summary/PR body.
type fixChange struct {
	File      string   `json:"file"`
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
rewrites the corresponding pins in the dependency manifests found under
--dir (requirements.txt today; the patcher interface leaves room for more
ecosystems).

Backports are same-version (<version>+cgr.N) — non-breaking by construction.
Findings needing an upstream upgrade or exception review are never touched;
they stay in the advisor report.

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

		// Collect backport pins: package → new version, plus the vuln IDs
		// each backport addresses.
		type update struct {
			to        string
			addresses []string
		}
		updates := map[string]update{}
		for _, r := range report.Recommendations {
			if r.Action != "backport" || r.ChainguardFix == "" {
				continue
			}
			name, version, ok := parseFix(r.ChainguardFix)
			if !ok || !strings.EqualFold(name, r.Pkg) {
				continue
			}
			u := updates[strings.ToLower(name)]
			u.to = version
			u.addresses = append(u.addresses, r.ID)
			updates[strings.ToLower(name)] = u
		}

		// Discover manifests and apply the pins.
		manifests, err := manifest.Discover(fixDir)
		if err != nil {
			return err
		}
		var changes []fixChange
		for _, path := range manifests {
			content, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("read %s: %w", path, err)
			}
			pins := map[string]string{}
			for name, u := range updates {
				pins[name] = u.to
			}
			rewritten, applied := manifest.Rewrite(string(content), pins)
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
					Package:   a.Name,
					From:      a.From,
					To:        a.To,
					Addresses: updates[a.Name].addresses,
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

// parseFix extracts "name==version" from the advisor's suggestion string,
// e.g. "werkzeug==2.2.3+cgr.1  (from https://libraries.cgr.dev/python/)".
func parseFix(s string) (name, version string, ok bool) {
	token, _, _ := strings.Cut(strings.TrimSpace(s), " ")
	name, version, ok = strings.Cut(token, "==")
	return name, version, ok && name != "" && version != ""
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
