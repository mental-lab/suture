package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/mental-lab/suture/internal/advise"
	"github.com/mental-lab/suture/internal/feed"
	"github.com/mental-lab/suture/internal/scan"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	scanDir       string
	adviseFormat  string
	adviseOut     string
	adviseGate    bool
	assetsPath    string
	assetKey      string
	advisePrefix  string
	adviseBaseURL string
)

var adviseCmd = &cobra.Command{
	Use:   "advise",
	Short: "Cross-reference scan findings with the OpenVEX feed and recommend remediations",
	Long: `Read Trivy or Grype scan results (auto-detected per file), look each
finding up in the Chainguard Libraries OpenVEX feed, and recommend a
remediation path: same-version backport, upstream upgrade/replacement, or
exception review.

Exit 0 always (advisory) unless --gate is passed, in which case it exits 1
when an internet-facing production asset has a Critical/High finding with a
Chainguard fix available that has not been applied.`,
	Example: `  suture advise --scan-dir results/ --format markdown --out vex-report.md
  suture advise --scan-dir results/ --assets security/asset-inventory.yaml --gate`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		findings, err := scan.LoadDir(scanDir)
		if err != nil {
			return err
		}
		findings, dropped := advise.LibrariesScope(findings)
		if len(dropped) > 0 {
			types := map[string]int{}
			for _, f := range dropped {
				eco, _, _ := strings.Cut(strings.TrimPrefix(f.PURL, "pkg:"), "/")
				types[eco]++
			}
			var parts []string
			for eco, n := range types {
				parts = append(parts, fmt.Sprintf("%s: %d", eco, n))
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "Skipped %d findings outside Chainguard Libraries ecosystems (%s)\n",
				len(dropped), strings.Join(parts, ", "))
		}
		if len(findings) == 0 {
			fmt.Fprintln(cmd.OutOrStdout(), "No findings in scan results — nothing to recommend.")
			return nil
		}

		facing, err := internetFacing(assetsPath, assetKey)
		if err != nil {
			return err
		}

		client := feed.New()
		client.BaseURL = adviseBaseURL
		advisor := advise.New(client, advisePrefix, facing)

		rows, err := advisor.Analyze(cmd.Context(), findings)
		if err != nil {
			return err
		}

		var report []byte
		if adviseFormat == "json" {
			report, err = advise.JSON(rows)
		} else {
			report = []byte(advise.Markdown(rows))
		}
		if err != nil {
			return err
		}

		if adviseOut != "" {
			if err := os.WriteFile(adviseOut, append(report, '\n'), 0o644); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Report written to %s\n", adviseOut)
		} else {
			fmt.Fprintln(cmd.OutOrStdout(), string(report))
		}

		if adviseGate {
			blocking := advise.Blocking(rows)
			if len(blocking) > 0 {
				fmt.Fprintf(cmd.OutOrStdout(),
					"\nGATE: %d internet-facing finding(s) have a Chainguard fix available but not applied — DENIED\n",
					len(blocking))
				os.Exit(1)
			}
		}
		return nil
	},
}

// internetFacing reads the asset inventory and returns whether the target
// asset is internet-exposed. With no --asset-key and exactly one asset in the
// inventory (the common single-service case), that asset is used.
func internetFacing(assetsPath, assetKey string) (bool, error) {
	if assetsPath == "" {
		return false, nil
	}
	data, err := os.ReadFile(assetsPath)
	if err != nil {
		return false, fmt.Errorf("read asset inventory: %w", err)
	}
	var inv struct {
		Assets map[string]struct {
			InternetExposed bool `yaml:"internet_exposed"`
		} `yaml:"assets"`
	}
	if err := yaml.Unmarshal(data, &inv); err != nil {
		return false, fmt.Errorf("parse asset inventory: %w", err)
	}
	key := assetKey
	if key == "" && len(inv.Assets) == 1 {
		for k := range inv.Assets {
			key = k
		}
	}
	if _, ok := inv.Assets[key]; !ok {
		return false, fmt.Errorf("asset %q not found in inventory", key)
	}
	return inv.Assets[key].InternetExposed, nil
}

func init() {
	adviseCmd.Flags().StringVar(&scanDir, "scan-dir", "", "directory of Trivy/Grype JSON scan results (required)")
	adviseCmd.Flags().StringVar(&adviseFormat, "format", "markdown", "output format: markdown or json")
	adviseCmd.Flags().StringVar(&adviseOut, "out", "", "write the report to a file instead of stdout")
	adviseCmd.Flags().BoolVar(&adviseGate, "gate", false, "exit 1 when an internet-facing Critical/High has an unapplied Chainguard fix")
	adviseCmd.Flags().StringVar(&assetsPath, "assets", "", "asset-inventory.yaml providing exposure context")
	adviseCmd.Flags().StringVar(&assetKey, "asset-key", "", "asset to attribute findings to (defaults to the only asset in --assets)")
	adviseCmd.Flags().StringVar(&advisePrefix, "index-prefix", "pypi", "OpenVEX feed entry prefix for this ecosystem")
	adviseCmd.Flags().StringVar(&adviseBaseURL, "base-url", feed.DefaultBaseURL, "OpenVEX feed base URL")
	_ = adviseCmd.MarkFlagRequired("scan-dir")
}
