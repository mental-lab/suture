package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/mental-lab/suture/internal/feed"
	"github.com/spf13/cobra"
)

var (
	fetchOut         string
	fetchDocsDir     string
	fetchBaseURL     string
	fetchConcurrency int
)

var fetchCmd = &cobra.Command{
	Use:   "fetch",
	Short: "Fetch the OpenVEX feed and build the fix cache",
	Long: `Fetch every per-package OpenVEX document from the Chainguard Libraries
feed and emit the OPA-consumable fix cache. Optionally materialize the raw
documents so Grype can consume them directly via --vex <dir> for VEX-aware
scanning that suppresses status=fixed findings.`,
	Example: `  suture fetch --out data/vex-cache.json
  suture fetch --out data/vex-cache.json --write-docs vex-documents`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		ctx := cmd.Context()
		client := feed.New()
		client.BaseURL = fetchBaseURL

		ids, err := client.Index(ctx)
		if err != nil {
			return fmt.Errorf("feed index: %w", err)
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
				if fetchDocsDir != "" {
					safe := strings.NewReplacer("/", "_", ":", "_").Replace(id)
					var pretty json.RawMessage = raw
					out, err := json.MarshalIndent(pretty, "", " ")
					if err == nil {
						_ = os.WriteFile(filepath.Join(fetchDocsDir, safe+".openvex.json"), out, 0o644)
					}
				}
			}(id)
		}
		wg.Wait()

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

func init() {
	fetchCmd.Flags().StringVar(&fetchOut, "out", "data/vex-cache.json", "path to write the fix cache")
	fetchCmd.Flags().StringVar(&fetchDocsDir, "write-docs", "", "directory to write raw per-package OpenVEX documents for Grype")
	fetchCmd.Flags().StringVar(&fetchBaseURL, "base-url", feed.DefaultBaseURL, "OpenVEX feed base URL")
	fetchCmd.Flags().IntVar(&fetchConcurrency, "concurrency", 8, "parallel document fetches")
}
