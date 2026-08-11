package manifest

import (
	"regexp"
	"strings"
)

var mavenPatcher = Patcher{
	Name: "maven",
	Matches: func(base string) bool {
		return base == "pom.xml"
	},
	Rewrite: rewritePom,
}

var (
	depBlockRe = regexp.MustCompile(`(?s)<dependency>.*?</dependency>`)
	groupRe    = regexp.MustCompile(`<groupId>\s*([^<]+?)\s*</groupId>`)
	artifactRe = regexp.MustCompile(`<artifactId>\s*([^<]+?)\s*</artifactId>`)
	versionRe  = regexp.MustCompile(`<version>\s*([^<]+?)\s*</version>`)
)

// rewritePom patches literal <version> elements inside <dependency> blocks
// whose groupId:artifactId matches an update. Property references
// (<version>${foo.version}</version>) are skipped — the literal never
// equals From, so they fall out naturally.
func rewritePom(data string, updates map[string]Update) (string, []Change) {
	var changes []Change
	out := depBlockRe.ReplaceAllStringFunc(data, func(block string) string {
		g := submatch(groupRe, block)
		a := submatch(artifactRe, block)
		v := submatch(versionRe, block)
		if g == "" || a == "" || v == "" {
			return block
		}
		u, ok := updates[g+":"+a]
		if !ok || v != u.From || u.To == u.From {
			return block
		}
		changes = append(changes, Change{
			Name: g + ":" + a,
			From: v,
			To:   u.To,
			Line: lineOf(data, strings.Index(data, block)),
		})
		return versionRe.ReplaceAllString(block, "<version>"+u.To+"</version>")
	})
	return out, changes
}

func submatch(re *regexp.Regexp, s string) string {
	m := re.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	return m[1]
}
