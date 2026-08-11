// Package manifest parses and rewrites Python requirements files,
// preserving everything except the version pins it is asked to change.
package manifest

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
)

// Discover finds dependency manifests under root, Gemnasium-style: known
// filenames, searched at most two levels deep. requirements.txt and
// requirements-*.txt / requirements/*.txt variants are supported.
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
			if depth >= 2 || (depth == 0 && strings.HasPrefix(d.Name(), ".") && d.Name() != ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasPrefix(d.Name(), "requirements") && strings.HasSuffix(d.Name(), ".txt") {
			found = append(found, path)
		}
		return nil
	})
	return found, err
}

// pinRe matches a pinned requirement line: name==version, with optional
// whitespace. Extras (pkg[extra]==1.0) are tolerated; the extras stay
// attached to the name on rewrite.
var pinRe = regexp.MustCompile(`^(\s*)([A-Za-z0-9_.-]+(?:\[[^\]]*\])?)\s*==\s*([^\s;#\\]+)(.*)$`)

// Requirement is one pinned line in a manifest.
type Requirement struct {
	Name    string // package name, lowercase, extras stripped
	Version string
	Line    int // 0-indexed line number
}

// Change is one applied pin update.
type Change struct {
	Name string
	From string
	To   string
	Line int
}

// ParseRequirements returns the pinned requirements (name==version lines).
// Everything else — comments, options, ranges, VCS/URL lines — is ignored.
func ParseRequirements(data string) []Requirement {
	var reqs []Requirement
	for i, line := range strings.Split(data, "\n") {
		m := pinRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name := m[2]
		if j := strings.Index(name, "["); j >= 0 {
			name = name[:j]
		}
		reqs = append(reqs, Requirement{
			Name:    strings.ToLower(name),
			Version: m[3],
			Line:    i,
		})
	}
	return reqs
}

// Rewrite returns the manifest with the given version pins updated
// (keyed by lowercase package name) and the list of changes applied.
// Lines not subject to an update are preserved byte-for-byte.
func Rewrite(data string, updates map[string]string) (string, []Change) {
	lines := strings.Split(data, "\n")
	var changes []Change
	for i, line := range lines {
		m := pinRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name := m[2]
		plain := name
		if j := strings.Index(plain, "["); j >= 0 {
			plain = plain[:j]
		}
		to, ok := updates[strings.ToLower(plain)]
		if !ok || to == m[3] {
			continue
		}
		lines[i] = fmt.Sprintf("%s%s==%s%s", m[1], name, to, m[4])
		changes = append(changes, Change{Name: strings.ToLower(plain), From: m[3], To: to, Line: i})
	}
	return strings.Join(lines, "\n"), changes
}
