// Package policy embeds and exports the default OPA/Rego gate policy.
package policy

import (
	_ "embed"
	"os"
	"path/filepath"
	"strings"
)

//go:embed default.rego
var defaultRego string

// Export writes the default gate policy to dir, substituting the asset key
// used to look up exposure context in the asset-inventory data document.
// Returns the path written.
func Export(dir, assetKey string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "remediation.rego")
	content := strings.ReplaceAll(defaultRego, "__ASSET_KEY__", assetKey)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return "", err
	}
	return path, nil
}
