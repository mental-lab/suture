package cmd

import (
	"fmt"

	"github.com/mental-lab/suture/internal/policy"
	"github.com/spf13/cobra"
)

var (
	policyDir      string
	policyAssetKey string
)

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage the default OPA/Rego gate policy",
}

var policyExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Write the default remediation gate policy into the repo",
	Long: `Writes remediation.rego, the OpenVEX-aware gate: it denies
internet-facing Critical/High findings that have a Chainguard fix available
but unapplied, and goes green once the backport is installed. Evaluate it
with Conftest against the scan output plus the generated data documents.`,
	Example: `  suture policy export --dir policy/vex --asset-key my-service`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		path, err := policy.Export(policyDir, policyAssetKey)
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Wrote %s\n", path)
		return nil
	},
}

func init() {
	policyExportCmd.Flags().StringVar(&policyDir, "dir", "policy/vex", "directory to write the policy")
	policyExportCmd.Flags().StringVar(&policyAssetKey, "asset-key", "app", "asset-inventory key the policy looks up for exposure context")
	policyCmd.AddCommand(policyExportCmd)
}
