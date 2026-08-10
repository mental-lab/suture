package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mental-lab/suture/internal/feed"
	"github.com/mental-lab/suture/internal/sbom"
	"github.com/spf13/cobra"
)

var (
	fetchOut          string
	fetchDocsDir      string
	fetchBaseURL      string
	fetchConcurrency  int
	fetchSBOM         string
	fetchPackages     []string
	fetchPackagesFile string
	fetchVexFile      string
)

var fetchCmd = &cobra.Command{
	Use:   "fetch",
	Short: "Fetch the OpenVEX feed and build the fix cache",
	Long: `Fetch per-package OpenVEX documents from the Chainguard Libraries feed
and emit the OPA-consumable fix cache. Optionally materialize the raw
documents so Grype can consume them directly via --vex <dir>, or a single
merged document via --write-vex for Trivy's --vex <file>, for
VEX-aware scanning that suppresses status=fixed findings.

By default the whole feed is fetched. Scope to the packages you ship with
--sbom (Syft/SPDX/CycloneDX JSON, or "-" for stdin), --packages (bare names
match every ecosystem; "eco/name" pins one), or --packages-file (one name
per line; requirements.txt works). Flags compose as a union.`,
	Example: `  suture fetch --out data/vex-cache.json
  suture fetch --sbom sbom.json --write-docs vex-documents
  syft . -o syft-json | suture fetch --sbom - --write-docs vex-documents
  suture fetch --packages werkzeug,flask --packages-file requirements.txt`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		ctx := cmd.Context()
		client := feed.New()
		client.BaseURL = fetchBaseURL

		ids, err := client.Index(ctx)
		if err != nil {
			return fmt.Errorf("feed index: %w", err)
		}

		wanted, explicit, err := fetchWanted(cmd)
		if err != nil {
			return err
		}
		if wanted != nil {
			before := len(ids)
			ids, explicit = filterIDs(ids, wanted, explicit)
			fmt.Fprintf(cmd.ErrOrStderr(), "Scoped feed to %d of %d documents\n", len(ids), before)
			for _, name := range explicit {
				fmt.Fprintf(cmd.ErrOrStderr(), "warn: no feed document matched %q\n", name)
			}
			if len(ids) == 0 {
				fmt.Fprintln(cmd.ErrOrStderr(), "warn: scope matched zero documents; cache will be empty and the gate cannot deny unapplied fixes")
			}
		}

		if fetchDocsDir != "" {
			if err := os.MkdirAll(fetchDocsDir, 0o755); err != nil {
				return err
			}
		}

		cache := feed.Cache{}
		var mu sync.Mutex
		var wg sync.WaitGroup
		sem := make(chan struct{}, fetchConcurrency)
		var raws [][]byte // for --write-vex

		for _, id := range ids {
			wg.Add(1)
			go func(id string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				raw, err := client.FetchRaw(ctx, id)
				if err != nil {
					fmt.Fprintf(os.Stderr, "warn: %s: %v\n", id, err)
					return
				}
				doc, err := feed.ParseDocument(raw)
				if err != nil {
					fmt.Fprintf(os.Stderr, "warn: %s: %v\n", id, err)
					return
				}
				mu.Lock()
				defer mu.Unlock()
				cache.Index(doc)
				if fetchVexFile != "" {
					raws = append(raws, raw)
				}
				if fetchDocsDir != "" {
					safe := strings.NewReplacer("/", "_", ":", "_").Replace(id)
					var pretty json.RawMessage = raw
					out, err := json.MarshalIndent(pretty, "", " ")
					if err == nil {
						_ = os.WriteFile(filepath.Join(fetchDocsDir, safe), out, 0o644)
					}
				}
			}(id)
		}
		wg.Wait()

		if fetchVexFile != "" {
			n, err := writeMergedVEX(fetchVexFile, raws)
			if err != nil {
				return fmt.Errorf("write merged VEX document: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Wrote %s: %d statements merged\n", fetchVexFile, n)
		}

		data, err := json.MarshalIndent(cache, "", " ")
		if err != nil {
			return err
		}
		if dir := filepath.Dir(fetchOut); dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return err
			}
		}
		if err := os.WriteFile(fetchOut, append(data, '\n'), 0o644); err != nil {
			return err
		}
		pkgs, fixes := cache.Stats()
		fmt.Fprintf(cmd.OutOrStdout(), "Wrote %s: %d packages, %d CVE fix mappings\n", fetchOut, pkgs, fixes)
		return nil
	},
}

// fetchWanted builds the set of wanted feed document keys from the scoping
// flags. Returns nil (no scoping) when no flag was given. The second return
// lists explicitly requested package names for unmatched-name warnings.
func fetchWanted(cmd *cobra.Command) (wanted []string, explicit []string, err error) {
	scoped := fetchSBOM != "" || len(fetchPackages) > 0 || fetchPackagesFile != ""
	if !scoped {
		return nil, nil, nil
	}

	if fetchSBOM != "" {
		var data []byte
		if fetchSBOM == "-" {
			data, err = io.ReadAll(cmd.InOrStdin())
		} else {
			data, err = os.ReadFile(fetchSBOM)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("read SBOM: %w", err)
		}
		purls, err := sbom.PURLs(data)
		if err != nil {
			return nil, nil, fmt.Errorf("--sbom: %w", err)
		}
		for _, p := range purls {
			if key, ok := feed.DocKey(p); ok {
				wanted = append(wanted, key)
			}
		}
	}

	for _, list := range fetchPackages {
		for _, name := range strings.Split(list, ",") {
			if name = strings.TrimSpace(name); name != "" {
				wanted = append(wanted, name)
				explicit = append(explicit, name)
			}
		}
	}

	if fetchPackagesFile != "" {
		data, err := os.ReadFile(fetchPackagesFile)
		if err != nil {
			return nil, nil, fmt.Errorf("read packages file: %w", err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			// Tolerate requirements.txt-style lines: strip version pins,
			// extras, options, and comments.
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
				continue
			}
			if i := strings.IndexAny(line, "=<>~[; "); i >= 0 {
				line = line[:i]
			}
			if name := strings.TrimSpace(line); name != "" {
				wanted = append(wanted, name)
				explicit = append(explicit, name)
			}
		}
	}
	return wanted, explicit, nil
}

// filterIDs keeps feed entry IDs whose document key matches any wanted key
// (feed.MatchKeys handles ecosystem pinning and name normalization). Returns
// the surviving IDs plus the explicitly requested names that matched
// nothing, for warning.
func filterIDs(ids, wanted, explicit []string) ([]string, []string) {
	matched := map[string]bool{}
	var out []string
	for _, id := range ids {
		key := feed.KeyFromID(id)
		for _, w := range wanted {
			if feed.MatchKeys(w, key) {
				out = append(out, id)
				matched[w] = true
				break
			}
		}
	}
	var unmatched []string
	for _, name := range explicit {
		if !matched[name] {
			unmatched = append(unmatched, name)
		}
	}
	sort.Strings(unmatched)
	return out, unmatched
}

// partialDoc peels the statements array off a raw OpenVEX document so
// documents can be merged without re-encoding their statements.
type partialDoc struct {
	Statements []json.RawMessage `json:"statements"`
}

// writeMergedVEX writes one OpenVEX document containing every fetched
// statement. Trivy's --vex accepts a file but not a directory; Grype takes
// either, so per-statement fidelity is preserved by carrying raw JSON.
func writeMergedVEX(path string, raws [][]byte) (int, error) {
	var stmts []json.RawMessage
	for _, raw := range raws {
		var d partialDoc
		if err := json.Unmarshal(raw, &d); err != nil {
			return 0, err
		}
		stmts = append(stmts, d.Statements...)
	}
	merged := map[string]any{
		"@context":   "https://openvex.dev/ns/v0.2.0",
		"@id":        "https://github.com/mental-lab/suture/vex/merged",
		"author":     "Chainguard Team (merged by suture fetch)",
		"version":    1,
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
		"statements": stmts,
	}
	data, err := json.MarshalIndent(merged, "", " ")
	if err != nil {
		return 0, err
	}
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return 0, err
		}
	}
	return len(stmts), os.WriteFile(path, append(data, '\n'), 0o644)
}

func init() {
	fetchCmd.Flags().StringVar(&fetchOut, "out", "data/vex-cache.json", "path to write the fix cache")
	fetchCmd.Flags().StringVar(&fetchDocsDir, "write-docs", "", "directory to write raw per-package OpenVEX documents for Grype")
	fetchCmd.Flags().StringVar(&fetchVexFile, "write-vex", "", "write one merged OpenVEX document (for Trivy --vex, which takes a file)")
	fetchCmd.Flags().StringVar(&fetchVexFile, "write-docs-file", "", "alias for --write-vex")
	_ = fetchCmd.Flags().MarkHidden("write-docs-file")
	fetchCmd.Flags().StringVar(&fetchBaseURL, "base-url", feed.DefaultBaseURL, "OpenVEX feed base URL")
	fetchCmd.Flags().IntVar(&fetchConcurrency, "concurrency", 8, "parallel document fetches")
	fetchCmd.Flags().StringVar(&fetchSBOM, "sbom", "", "SBOM to scope the fetch (Syft/SPDX/CycloneDX JSON, or \"-\" for stdin)")
	fetchCmd.Flags().StringSliceVar(&fetchPackages, "packages", nil, "comma-separated package names (bare or eco/name) to scope the fetch")
	fetchCmd.Flags().StringVar(&fetchPackagesFile, "packages-file", "", "file of package names, one per line (requirements.txt works)")
}
