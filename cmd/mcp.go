package cmd

import (
	"github.com/mental-lab/suture/internal/feed"
	"github.com/mental-lab/suture/internal/mcpserver"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"
)

var mcpBaseURL string

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Expose optional read-only remediation evidence over MCP (stdio)",
	Long: `Start an optional stdio Model Context Protocol server exposing read-only tools:

  check_fix   — is there a Chainguard backport for this CVE in this package?
  list_fixes  — every vulnerability with a fixed release for a package
  advise      — remediation paths for a directory of Trivy/Grype scan results

This is an interactive evidence adapter, not the authoritative automation
path. CI and policy should consume suture advise --format json directly.

For clients that read .mcp.json:

  {"mcpServers": {"suture": {"command": "suture", "args": ["mcp"]}}}`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		client := feed.New()
		client.BaseURL = mcpBaseURL
		return mcpserver.New(client, Version).Run(cmd.Context(), &mcp.StdioTransport{})
	},
}

func init() {
	mcpCmd.Flags().StringVar(&mcpBaseURL, "base-url", feed.DefaultBaseURL, "OpenVEX feed base URL")
}
