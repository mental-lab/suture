package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Version is stamped at release time via
// -ldflags "-X github.com/mental-lab/suture/cmd.Version=...".
var Version = "dev"

var rootCmd = &cobra.Command{
	Use:   "suture",
	Short: "OpenVEX-aware remediation tooling for Chainguard Libraries",
	Long: `Cross-reference vulnerability scanner output against the Chainguard
Libraries OpenVEX feed to find same-version backports (+cgr.N), recommend
remediation paths, and gate merges on unapplied fixes.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.Version = Version
	rootCmd.AddCommand(fetchCmd, adviseCmd, policyCmd, mcpCmd)
}
