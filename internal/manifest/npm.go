package manifest

import (
	"regexp"
)

var npmPatcher = Patcher{
	Name: "npm",
	Matches: func(base string) bool {
		return base == "package.json"
	},
	Rewrite: rewritePackageJSON,
}

// rewritePackageJSON patches exact pins ("name": "1.2.3") in place,
// preserving formatting. Range pins (^, ~) float already — there is no pin
// to backport, so they are never touched.
func rewritePackageJSON(data string, updates map[string]Update) (string, []Change) {
	out := data
	var changes []Change
	for name, u := range updates {
		if u.From == u.To {
			continue
		}
		// "name": "from"  — exact pin on one line.
		re := regexp.MustCompile(`(?m)^(\s*)"` + regexp.QuoteMeta(name) + `"(\s*:\s*)"` + regexp.QuoteMeta(u.From) + `"`)
		loc := re.FindStringIndex(out)
		if loc == nil {
			continue
		}
		out = re.ReplaceAllString(out, `${1}"`+name+`"${2}"`+u.To+`"`)
		changes = append(changes, Change{Name: name, From: u.From, To: u.To, Line: lineOf(data, loc[0])})
	}
	return out, changes
}
