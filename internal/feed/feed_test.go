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
