package sbom

import (
	"slices"
	"testing"
)

func TestPURLsSyft(t *testing.T) {
	doc := `{"artifacts": [
		{"name": "werkzeug", "version": "2.2.3", "purl": "pkg:pypi/werkzeug@2.2.3"},
		{"name": "flask", "version": "2.2.5", "purl": "pkg:pypi/flask@2.2.5"},
		{"name": "nopurl"}
	]}`
	got, err := PURLs([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"pkg:pypi/werkzeug", "pkg:pypi/flask"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestPURLsSPDX(t *testing.T) {
	doc := `{"spdxVersion": "SPDX-2.3", "packages": [
		{"name": "werkzeug", "externalRefs": [
			{"referenceType": "purl", "referenceLocator": "pkg:pypi/werkzeug@2.2.3"},
			{"referenceType": "cpe23Type", "referenceLocator": "cpe:2.3:a:palletsprojects:werkzeug:2.2.3"}
		]},
		{"name": "log4j-core", "externalRefs": [
			{"referenceType": "purl", "referenceLocator": "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1"}
		]}
	]}`
	got, err := PURLs([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"pkg:pypi/werkzeug", "pkg:maven/org.apache.logging.log4j/log4j-core"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestPURLsCycloneDX(t *testing.T) {
	doc := `{"bomFormat": "CycloneDX", "components": [
		{"name": "@angular/core", "purl": "pkg:npm/%40angular/core@16.0.0"},
		{"name": "lodash", "purl": "pkg:npm/lodash@4.17.21"}
	]}`
	got, err := PURLs([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"pkg:npm/%40angular/core", "pkg:npm/lodash"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestPURLsUnrecognized(t *testing.T) {
	if _, err := PURLs([]byte(`{"foo": 1}`)); err == nil {
		t.Fatal("expected error for unrecognized format")
	}
	if _, err := PURLs([]byte(`not json`)); err == nil {
		t.Fatal("expected error for non-JSON input")
	}
}
