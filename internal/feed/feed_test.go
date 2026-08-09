package feed

import "testing"

const testDoc = `{
  "statements": [
    {
      "status": "fixed",
      "vulnerability": {"name": "CVE-2023-25577", "aliases": ["GHSA-xrfv-9qxx-8jxp"]},
      "products": [
        {"identifiers": {"purl": "pkg:pypi/werkzeug@2.2.3%2Bcgr.1"}},
        {"identifiers": {}}
      ]
    },
    {
      "status": "not_affected",
      "vulnerability": {"name": "CVE-0000-0001"},
      "products": [{"identifiers": {"purl": "pkg:pypi/werkzeug@2.2.3"}}]
    }
  ]
}`

func TestCacheIndex(t *testing.T) {
	doc, err := ParseDocument([]byte(testDoc))
	if err != nil {
		t.Fatal(err)
	}
	cache := Cache{}
	cache.Index(doc)

	byID := cache["pkg:pypi/werkzeug"]
	if byID == nil {
		t.Fatal("expected pkg:pypi/werkzeug in cache")
	}
	// Keyed by every identifier so CVE- and GHSA-reporting scanners both match.
	for _, id := range []string{"CVE-2023-25577", "GHSA-xrfv-9qxx-8jxp"} {
		got := byID[id]
		if len(got) != 1 || got[0] != "pkg:pypi/werkzeug@2.2.3%2Bcgr.1" {
			t.Errorf("cache[%q] = %v, want the fixed purl", id, got)
		}
	}
	// Only status=fixed statements are indexed.
	if _, ok := byID["CVE-0000-0001"]; ok {
		t.Error("not_affected statement must not be indexed")
	}
}

func TestStats(t *testing.T) {
	doc, _ := ParseDocument([]byte(testDoc))
	cache := Cache{}
	cache.Index(doc)
	pkgs, fixes := cache.Stats()
	if pkgs != 1 || fixes != 2 {
		t.Errorf("Stats() = (%d, %d), want (1, 2)", pkgs, fixes)
	}
}

func TestDocKey(t *testing.T) {
	cases := map[string]string{
		"pkg:pypi/werkzeug":                                    "pypi/werkzeug",
		"pkg:pypi/werkzeug@2.2.3":                              "pypi/werkzeug",
		"pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1": "maven/org.apache.logging.log4j_log4j-core",
		"pkg:npm/%40angular/core@16.0.0":                       "npm/@angular_core",
		"pkg:nuget/Newtonsoft.Json@13.0.3":                     "nuget/Newtonsoft.Json",
	}
	for purl, want := range cases {
		got, ok := DocKey(purl)
		if !ok || got != want {
			t.Errorf("DocKey(%q) = %q, %v; want %q", purl, got, ok, want)
		}
	}
	for _, bad := range []string{"werkzeug", "pkg:werkzeug", ""} {
		if _, ok := DocKey(bad); ok {
			t.Errorf("DocKey(%q) unexpectedly succeeded", bad)
		}
	}
}

func TestMatchKeys(t *testing.T) {
	cases := []struct {
		want, have string
		match      bool
	}{
		{"pypi/werkzeug", "pypi/werkzeug", true},
		{"werkzeug", "pypi/werkzeug", true}, // bare name matches any ecosystem
		{"pypi/Flask", "pypi/flask", true},
		{"pypi/typing-extensions", "pypi/typing_extensions", true},
		{"maven/org.apache.logging.log4j_log4j-core", "maven/org.apache.logging.log4j_log4j-core", true},
		{"pypi/werkzeug", "maven/werkzeug", false}, // pinned ecosystem
		{"flask", "pypi/werkzeug", false},
	}
	for _, c := range cases {
		if got := MatchKeys(c.want, c.have); got != c.match {
			t.Errorf("MatchKeys(%q, %q) = %v; want %v", c.want, c.have, got, c.match)
		}
	}
}
