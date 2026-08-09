// Package mcpserver exposes suture's feed lookups and remediation advice as
// read-only MCP tools, so AI coding assistants can answer "is there a
// Chainguard fix for this CVE?" mid-conversation.
package mcpserver

import (
	"context"
	"fmt"
	"strings"

	"github.com/mental-lab/suture/internal/advise"
	"github.com/mental-lab/suture/internal/feed"
	"github.com/mental-lab/suture/internal/scan"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var readOnly = &mcp.ToolAnnotations{ReadOnlyHint: true}

// New returns an MCP server backed by the given feed client.
func New(client *feed.Client, version string) *mcp.Server {
	s := &server{client: client}
	mcpSrv := mcp.NewServer(&mcp.Implementation{Name: "suture", Version: version}, nil)
	mcp.AddTool(mcpSrv, &mcp.Tool{
		Name: "check_fix",
		Description: "Check whether the Chainguard Libraries OpenVEX feed records a same-version " +
			"backported fix for a vulnerability in a package. Package is a purl " +
			"(pkg:pypi/werkzeug) or feed key (pypi/werkzeug). Returns the fixed " +
			"versions (e.g. 2.2.3+cgr.1), newest first, or that no coverage exists.",
		Annotations: readOnly,
	}, s.checkFix)
	mcp.AddTool(mcpSrv, &mcp.Tool{
		Name: "list_fixes",
		Description: "List every vulnerability with a Chainguard-built fixed release for a " +
			"package, per the OpenVEX feed. Package is a purl (pkg:maven/org.apache.logging.log4j/log4j-core) " +
			"or feed key. Useful when triaging several CVEs against one dependency.",
		Annotations: readOnly,
	}, s.listFixes)
	mcp.AddTool(mcpSrv, &mcp.Tool{
		Name: "advise",
		Description: "Cross-reference a directory of Trivy/Grype JSON scan results with the " +
			"Chainguard OpenVEX feed and return a remediation path per finding: backport, " +
			"upgrade-or-replace, exception-review, or already fixed. Findings outside " +
			"Chainguard Libraries ecosystems are skipped.",
		Annotations: readOnly,
	}, s.adviseScan)
	return mcpSrv
}

type server struct {
	client *feed.Client
}

type checkFixArgs struct {
	Package       string `json:"package" jsonschema:"purl (pkg:pypi/werkzeug) or feed key (pypi/werkzeug)"`
	Vulnerability string `json:"vulnerability" jsonschema:"CVE or GHSA identifier, e.g. CVE-2023-25577"`
}

type fixResult struct {
	Package string   `json:"package"`
	VulnID  string   `json:"vulnerability"`
	Fixes   []string `json:"fixes,omitempty"`
	Note    string   `json:"note,omitempty"`
}

func (s *server) checkFix(ctx context.Context, _ *mcp.CallToolRequest, args checkFixArgs) (*mcp.CallToolResult, fixResult, error) {
	doc, err := s.doc(ctx, args.Package)
	if err != nil {
		return nil, fixResult{}, err
	}
	res := fixResult{Package: args.Package, VulnID: args.Vulnerability}
	if doc == nil {
		res.Note = "no feed document — Chainguard Libraries publishes no remediation data for this package"
		return nil, res, nil
	}
	fixes := advise.ChainguardFixes(doc, args.Vulnerability)
	if len(fixes) == 0 {
		res.Note = "package is in the feed, but no fixed statement matches this vulnerability"
		return nil, res, nil
	}
	res.Fixes = fixes
	return nil, res, nil
}

type listFixesArgs struct {
	Package string `json:"package" jsonschema:"purl (pkg:pypi/werkzeug) or feed key (pypi/werkzeug)"`
}

type listFixesResult struct {
	Package string            `json:"package"`
	Fixes   map[string]string `json:"fixes,omitempty"` // vulnerability → newest fixed version
	Note    string            `json:"note,omitempty"`
}

func (s *server) listFixes(ctx context.Context, _ *mcp.CallToolRequest, args listFixesArgs) (*mcp.CallToolResult, listFixesResult, error) {
	doc, err := s.doc(ctx, args.Package)
	if err != nil {
		return nil, listFixesResult{}, err
	}
	res := listFixesResult{Package: args.Package}
	if doc == nil {
		res.Note = "no feed document — Chainguard Libraries publishes no remediation data for this package"
		return nil, res, nil
	}
	res.Fixes = map[string]string{}
	for _, stmt := range doc.Statements {
		if stmt.Status != "fixed" {
			continue
		}
		fixes := advise.ChainguardFixes(&feed.Document{Statements: []feed.Statement{stmt}}, stmt.Vulnerability.Name)
		if len(fixes) == 0 {
			continue
		}
		res.Fixes[stmt.Vulnerability.Name] = advise.VersionOf(fixes[0])
	}
	if len(res.Fixes) == 0 {
		res.Note = "package is in the feed but has no fixed statements"
	}
	return nil, res, nil
}

type adviseArgs struct {
	ScanDir        string `json:"scan_dir" jsonschema:"directory containing Trivy or Grype JSON scan results"`
	InternetFacing bool   `json:"internet_facing" jsonschema:"whether the scanned asset is internet-exposed (drives upgrade-or-replace vs exception-review)"`
}

type adviseResult struct {
	Findings int          `json:"findings"`
	Skipped  int          `json:"skipped_out_of_scope"`
	Rows     []advise.Row `json:"rows"`
}

func (s *server) adviseScan(ctx context.Context, _ *mcp.CallToolRequest, args adviseArgs) (*mcp.CallToolResult, adviseResult, error) {
	findings, err := scan.LoadDir(args.ScanDir)
	if err != nil {
		return nil, adviseResult{}, fmt.Errorf("read scan: %w", err)
	}
	findings, dropped := advise.LibrariesScope(findings)
	advisor := advise.New(s.client, "pypi", args.InternetFacing)
	rows, err := advisor.Analyze(ctx, findings)
	if err != nil {
		return nil, adviseResult{}, err
	}
	return nil, adviseResult{Findings: len(rows), Skipped: len(dropped), Rows: rows}, nil
}

// doc fetches the per-package OpenVEX document; nil when the feed has no
// document for the package.
func (s *server) doc(ctx context.Context, pkg string) (*feed.Document, error) {
	id := entryID(pkg)
	ids, err := s.client.Index(ctx)
	if err != nil {
		return nil, fmt.Errorf("feed index: %w", err)
	}
	found := false
	for _, have := range ids {
		if have == id {
			found = true
			break
		}
	}
	if !found {
		return nil, nil
	}
	raw, err := s.client.FetchRaw(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", id, err)
	}
	return feed.ParseDocument(raw)
}

// entryID normalizes a purl or feed key to a feed document ID:
// "pkg:pypi/werkzeug" and "pypi/werkzeug" both → "pypi/werkzeug.openvex.json".
func entryID(pkg string) string {
	key := strings.TrimSuffix(strings.TrimPrefix(pkg, "pkg:"), ".openvex.json")
	return key + ".openvex.json"
}
