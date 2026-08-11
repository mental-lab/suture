package manifest

import (
	"os"
	"path/filepath"
	"testing"
)

const sample = `# app deps
Flask==2.2.5
Werkzeug==2.2.3  # web toolkit
requests[socks]==2.31.0
gunicorn>=22
-e .
# comment line

pytest==8.3.3
`

func TestParseRequirements(t *testing.T) {
	reqs := ParseRequirements(sample)
	got := map[string]string{}
	for _, r := range reqs {
		got[r.Name] = r.Version
	}
	want := map[string]string{
		"flask":    "2.2.5",
		"werkzeug": "2.2.3",
		"requests": "2.31.0",
		"pytest":   "8.3.3",
	}
	if len(reqs) != len(want) {
		t.Fatalf("ParseRequirements() = %v, want keys %v", got, want)
	}
	for name, v := range want {
		if got[name] != v {
			t.Errorf("%s = %q, want %q", name, got[name], v)
		}
	}
}

func TestRewrite(t *testing.T) {
	out, changes := Rewrite(sample, map[string]string{"werkzeug": "2.2.3+cgr.1", "flask": "2.2.5"})
	if len(changes) != 1 {
		t.Fatalf("changes = %v, want 1 (flask is already at the target)", changes)
	}
	c := changes[0]
	if c.Name != "werkzeug" || c.From != "2.2.3" || c.To != "2.2.3+cgr.1" {
		t.Errorf("unexpected change: %+v", c)
	}
	wantLine := "Werkzeug==2.2.3+cgr.1  # web toolkit"
	found := false
	for _, line := range splitLines(out) {
		if line == wantLine {
			found = true
		}
	}
	if !found {
		t.Errorf("rewritten manifest missing %q:\n%s", wantLine, out)
	}
	// Everything else preserved byte-for-byte.
	before, after := splitLines(sample), splitLines(out)
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

func TestDiscover(t *testing.T) {
	root := t.TempDir()
	write := func(rel string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("Flask==2.2.5\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("requirements.txt")
	write("api/requirements.txt")
	write("api/service/requirements.txt") // depth 2 — still found
	write("api/notes.txt")
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(".git/requirements.txt") // hidden dirs skipped

	found, err := Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 3 {
		t.Fatalf("Discover() = %v, want 3 manifests", found)
	}
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	return append(lines, s[start:])
}
