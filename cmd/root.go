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
	Short: "Turn OpenVEX backports into deterministic remediation plans",
	Long: `Cross-reference vulnerability scanner output against an OpenVEX feed,
identify same-upstream-version backports (+cgr.N and -0.cgr.N), and emit
machine-readable remediation plans for policy, existing developer tooling,
and reviewable dependency changes.`,
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
	rootCmd.AddCommand(fetchCmd, adviseCmd, mcpCmd)
}
