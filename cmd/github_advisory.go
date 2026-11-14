package cmd

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/mental-lab/suture/internal/githubadvisory"
	"github.com/spf13/cobra"
)

var (
	githubAdvisoryFrom     string
	githubAdvisoryOut      string
	githubAdvisoryModified string
)

var githubAdvisoryCmd = &cobra.Command{
	Use:   "github-advisory",
	Short: "Export GitHub enterprise innersource advisory payloads",
}

var githubAdvisoryExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Convert a remediation plan to GitHub's OSV 1.4 sync payload",
	Long: `Convert unapplied same-upstream-version backports from suture advise JSON
into the OSV 1.4 request body accepted by GitHub's enterprise innersource
vulnerability sync API.

The command validates required CVSS and package evidence but does not upload,
authenticate, or guarantee that Dependabot can resolve the fixed artifact.`,
	Example: `  suture github-advisory export --from remediation-plan.json --out github-advisories.json
  GH_TOKEN="$GITHUB_APP_INSTALLATION_TOKEN" gh api --method POST \
    /enterprises/ENTERPRISE/innersource-vulnerabilities/sync --input github-advisories.json`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		var data []byte
		var err error
		if githubAdvisoryFrom == "" || githubAdvisoryFrom == "-" {
			data, err = io.ReadAll(cmd.InOrStdin())
		} else {
			data, err = os.ReadFile(githubAdvisoryFrom)
		}
		if err != nil {
			return fmt.Errorf("read remediation plan: %w", err)
		}

		modified := time.Now().UTC().Truncate(time.Second)
		if githubAdvisoryModified != "" {
			modified, err = time.Parse(time.RFC3339, githubAdvisoryModified)
			if err != nil {
				return fmt.Errorf("parse --modified as RFC3339: %w", err)
			}
		}
		payload, err := githubadvisory.Export(data, modified)
		if err != nil {
			return err
		}
		payload = append(payload, '\n')
		if githubAdvisoryOut == "" || githubAdvisoryOut == "-" {
			_, err = cmd.OutOrStdout().Write(payload)
			return err
		}
		if err := os.WriteFile(githubAdvisoryOut, payload, 0o644); err != nil {
			return fmt.Errorf("write advisory payload: %w", err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "GitHub advisory payload written to %s\n", githubAdvisoryOut)
		return nil
	},
}

func init() {
	githubAdvisoryExportCmd.Flags().StringVar(&githubAdvisoryFrom, "from", "-", "advisor JSON report to read (path, or - for stdin)")
	githubAdvisoryExportCmd.Flags().StringVar(&githubAdvisoryOut, "out", "-", "write the GitHub sync payload to a file (or - for stdout)")
	githubAdvisoryExportCmd.Flags().StringVar(&githubAdvisoryModified, "modified", "", "OSV modified timestamp in RFC3339 (default: current UTC time)")
	githubAdvisoryCmd.AddCommand(githubAdvisoryExportCmd)
	rootCmd.AddCommand(githubAdvisoryCmd)
}
