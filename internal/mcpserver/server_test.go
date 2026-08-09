package mcpserver

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mental-lab/suture/internal/feed"
)

func fakeFeed(t *testing.T) *feed.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/all.json":
			fmt.Fprint(w, `{"entries": [{"id": "pypi/werkzeug.openvex.json"}]}`)
		case "/pypi/werkzeug.openvex.json":
			fmt.Fprint(w, `{"statements": [{
			  "status": "fixed",
			  "vulnerability": {"name": "CVE-2023-25577", "aliases": ["GHSA-xrfv-9qxx-8jxp"]},
			  "products": [{"identifiers": {"purl": "pkg:pypi/werkzeug@2.2.3%2Bcgr.1"}}]
			}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	c := feed.New()
	c.BaseURL = srv.URL
	return c
}

func TestCheckFix(t *testing.T) {
	s := &server{client: fakeFeed(t)}

	_, res, err := s.checkFix(context.Background(), nil, checkFixArgs{Package: "pkg:pypi/werkzeug", Vulnerability: "GHSA-xrfv-9qxx-8jxp"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Fixes) != 1 || !strings.Contains(res.Fixes[0], "2.2.3%2Bcgr.1") {
		t.Errorf("fixes = %v, want the +cgr.1 purl (matched via alias)", res.Fixes)
	}

	_, res, err = s.checkFix(context.Background(), nil, checkFixArgs{Package: "pypi/werkzeug", Vulnerability: "CVE-9999-0000"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Fixes) != 0 || !strings.Contains(res.Note, "no fixed statement") {
		t.Errorf("unknown CVE should note no matching statement, got %+v", res)
	}

	_, res, err = s.checkFix(context.Background(), nil, checkFixArgs{Package: "pypi/nosuchpkg", Vulnerability: "CVE-2023-25577"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Fixes) != 0 || !strings.Contains(res.Note, "no feed document") {
		t.Errorf("unknown package should note no feed document, got %+v", res)
	}
}

func TestListFixes(t *testing.T) {
	s := &server{client: fakeFeed(t)}
	_, res, err := s.listFixes(context.Background(), nil, listFixesArgs{Package: "pypi/werkzeug"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Fixes["CVE-2023-25577"] != "2.2.3+cgr.1" {
		t.Errorf("fixes = %v, want CVE-2023-25577 → 2.2.3+cgr.1 (decoded)", res.Fixes)
	}
}

func TestEntryID(t *testing.T) {
	for in, want := range map[string]string{
		"pkg:pypi/werkzeug":           "pypi/werkzeug.openvex.json",
		"pypi/werkzeug":               "pypi/werkzeug.openvex.json",
		"pkg:maven/com.h2database/h2": "maven/com.h2database/h2.openvex.json",
		"pypi/werkzeug.openvex.json":  "pypi/werkzeug.openvex.json",
	} {
		if got := entryID(in); got != want {
			t.Errorf("entryID(%q) = %q, want %q", in, got, want)
		}
	}
}
