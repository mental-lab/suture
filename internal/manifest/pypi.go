package manifest

import (
	"fmt"
	"regexp"
	"strings"
)

// pinRe matches a pinned requirement line: name==version, with optional
// whitespace and trailing comment/extras. Options, ranges, and VCS/URL
// lines never match.
var pinRe = regexp.MustCompile(`^(\s*)([A-Za-z0-9_.-]+(?:\[[^\]]*\])?)\s*==\s*([^\s;#\\]+)(.*)$`)

var pypiPatcher = Patcher{
	Name: "pypi",
	Matches: func(base string) bool {
		return strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt")
	},
	Rewrite: func(data string, updates map[string]Update) (string, []Change) {
		lines := splitLines(data)
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
			u, ok := updates[strings.ToLower(plain)]
			if !ok || m[3] != u.From || u.To == u.From {
				continue
			}
			lines[i] = fmt.Sprintf("%s%s==%s%s", m[1], name, u.To, m[4])
			changes = append(changes, Change{Name: strings.ToLower(plain), From: m[3], To: u.To, Line: i})
		}
		return strings.Join(lines, "\n"), changes
	},
}
