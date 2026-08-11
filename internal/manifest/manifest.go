// Package manifest discovers dependency manifests in a repository and
// rewrites version pins, preserving everything else byte-for-byte.
//
// One Patcher per ecosystem (pypi/npm/maven); each is an edit strategy
// only — no resolution, no dependency graphs. Adding an ecosystem means
// adding one Patcher to the registry.
package manifest

import (
	"io/fs"
	"path/filepath"
	"strings"
)

// Update is a requested pin change. Patchers apply it only when the
// manifest's current version equals From — never touch a pin that has
// already moved.
type Update struct {
	From string
	To   string
}

// Change is one applied pin update.
type Change struct {
	Name string
	From string
	To   string
	Line int // 0-indexed line number, -1 when not line-oriented
}

// Patcher edits one manifest format. Names are the ecosystem label used in
// purl types (pypi, npm, maven).
type Patcher struct {
	Name string
	// Matches reports whether this patcher handles the file (basename).
	Matches func(base string) bool
	// Rewrite applies updates (keyed by the ecosystem's package naming:
	// pypi = lowercase name, npm = name with scope, maven = group:artifact).
	Rewrite func(data string, updates map[string]Update) (string, []Change)
}

// Patchers is the ecosystem registry.
var Patchers = []Patcher{pypiPatcher, npmPatcher, mavenPatcher}

// skippedDirs are never descended into during discovery.
var skippedDirs = map[string]bool{
	"node_modules": true,
	"vendor":       true,
	"target":       true,
}

// Discover finds dependency manifests under root, Gemnasium-style: known
// filenames, at most two levels deep, hidden and vendored dirs skipped.
func Discover(root string) ([]string, error) {
	var found []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		depth := strings.Count(rel, string(filepath.Separator))
		if d.IsDir() {
			if depth >= 2 || skippedDirs[d.Name()] ||
				(depth == 0 && strings.HasPrefix(d.Name(), ".") && d.Name() != ".") {
				return filepath.SkipDir
			}
			return nil
		}
		for _, p := range Patchers {
			if p.Matches(d.Name()) {
				found = append(found, path)
				break
			}
		}
		return nil
	})
	return found, err
}

// PatcherFor returns the patcher handling the given file, by basename.
func PatcherFor(path string) *Patcher {
	base := filepath.Base(path)
	for i := range Patchers {
		if Patchers[i].Matches(base) {
			return &Patchers[i]
		}
	}
	return nil
}

func splitLines(s string) []string {
	return strings.Split(s, "\n")
}

// lineOf returns the 0-indexed line number containing byte offset i.
func lineOf(data string, i int) int {
	return strings.Count(data[:i], "\n")
}
