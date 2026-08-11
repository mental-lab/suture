package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const pypiSample = `# app deps
Flask==2.2.5
Werkzeug==2.2.3  # web toolkit
requests[socks]==2.31.0
gunicorn>=22
-e .
pytest==8.3.3
`

func TestPyPIRewrite(t *testing.T) {
	p := PatcherFor("requirements.txt")
	if p == nil || p.Name != "pypi" {
		t.Fatal("no pypi patcher for requirements.txt")
	}
	out, changes := p.Rewrite(pypiSample, map[string]Update{
		"werkzeug": {From: "2.2.3", To: "2.2.3+cgr.1"},
		"flask":    {From: "2.2.4", To: "2.2.5+cgr.1"}, // stale From: must not touch
	})
	if len(changes) != 1 {
		t.Fatalf("changes = %v, want exactly the werkzeug backport", changes)
	}
	c := changes[0]
	if c.Name != "werkzeug" || c.From != "2.2.3" || c.To != "2.2.3+cgr.1" {
		t.Errorf("unexpected change: %+v", c)
	}
	if !strings.Contains(out, "Werkzeug==2.2.3+cgr.1  # web toolkit") {
		t.Errorf("case/comment not preserved:\n%s", out)
	}
	if !strings.Contains(out, "Flask==2.2.5") {
		t.Error("flask pin changed despite stale From")
	}
	before, after := splitLines(pypiSample), splitLines(out)
	if len(before) != len(after) {
		t.Fatalf("line count changed: %d -> %d", len(before), len(after))
	}
	for i := range before {
		if i == c.Line {
			continue
		}
		if before[i] != after[i] {
			t.Errorf("line %d changed unexpectedly: %q -> %q", i, before[i], after[i])
		}
	}
}

const npmSample = `{
  "name": "app",
  "dependencies": {
    "lodash": "4.17.20",
    "@scope/pkg": "1.0.0",
    "react": "^18.2.0"
  },
  "devDependencies": {
    "lodash": "4.17.20"
  }
}
`

func TestNpmRewrite(t *testing.T) {
	p := PatcherFor("package.json")
	if p == nil || p.Name != "npm" {
		t.Fatal("no npm patcher for package.json")
	}
	out, changes := p.Rewrite(npmSample, map[string]Update{
		"lodash":     {From: "4.17.20", To: "4.17.20+cgr.1"},
		"@scope/pkg": {From: "1.0.0", To: "1.0.0+cgr.1"},
		"react":      {From: "18.2.0", To: "18.2.0+cgr.1"}, // range pin: no match
	})
	if len(changes) != 2 {
		t.Fatalf("changes = %v, want lodash + @scope/pkg only", changes)
	}
	if !strings.Contains(out, `"lodash": "4.17.20+cgr.1"`) {
		t.Error("lodash pin not updated")
	}
	if !strings.Contains(out, `"@scope/pkg": "1.0.0+cgr.1"`) {
		t.Error("scoped pin not updated")
	}
	if !strings.Contains(out, `"react": "^18.2.0"`) {
		t.Error("range pin touched")
	}
	if strings.Count(out, "4.17.20+cgr.1") != 2 {
		t.Error("both dependencies and devDependencies entries should update")
	}
}

const mavenSample = `<project>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>3.12.0</version>
    </dependency>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>${guava.version}</version>
    </dependency>
  </dependencies>
</project>
`

func TestMavenRewrite(t *testing.T) {
	p := PatcherFor("pom.xml")
	if p == nil || p.Name != "maven" {
		t.Fatal("no maven patcher for pom.xml")
	}
	out, changes := p.Rewrite(mavenSample, map[string]Update{
		"org.apache.commons:commons-lang3": {From: "3.12.0", To: "3.12.0+cgr.1"},
		"com.google.guava:guava":           {From: "32.0.0", To: "32.0.0+cgr.1"}, // property ref: skipped
	})
	if len(changes) != 1 {
		t.Fatalf("changes = %v, want commons-lang3 only", changes)
	}
	if !strings.Contains(out, "<version>3.12.0+cgr.1</version>") {
		t.Errorf("version not updated:\n%s", out)
	}
	if !strings.Contains(out, "${guava.version}") {
		t.Error("property-referenced version touched")
	}
}

func TestDiscover(t *testing.T) {
	root := t.TempDir()
	write := func(rel string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("requirements.txt")
	write("api/requirements.txt")
	write("api/service/requirements.txt") // depth 2 — still found
	write("web/package.json")
	write("service/pom.xml")
	write("api/notes.txt")
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(".git/requirements.txt")   // hidden dirs skipped
	write("web/node_modules/pkg/package.json") // vendored dirs skipped

	found, err := Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 5 {
		t.Fatalf("Discover() = %v, want 5 manifests", found)
	}
}
