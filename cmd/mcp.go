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
	Short: "Serve suture's feed lookups and remediation advice as MCP tools (stdio)",
	Long: `Start a stdio Model Context Protocol server exposing read-only tools:

  check_fix   — is there a Chainguard backport for this CVE in this package?
  list_fixes  — every vulnerability with a fixed release for a package
  advise      — remediation paths for a directory of Trivy/Grype scan results

Point an AI coding assistant at it, e.g. in .mcp.json:

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
