package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/quay/claircore"

	"github.com/quay/clair/v4/layerreport"
)

type bufferWriteCloser struct {
	*bytes.Buffer
}

func (bufferWriteCloser) Close() error { return nil }

func TestTextFormatterLayer(t *testing.T) {
	layer, err := claircore.ParseDigest("sha256:" + strings.Repeat("11", 32))
	if err != nil {
		t.Fatal(err)
	}
	r := layerreport.Build(&claircore.VulnerabilityReport{
		Packages: map[string]*claircore.Package{
			"1": {ID: "1", Name: "openssl", Version: "1.0.2"},
		},
		Environments: map[string][]*claircore.Environment{
			"1": {{IntroducedIn: layer}},
		},
		Vulnerabilities: map[string]*claircore.Vulnerability{
			"2": {ID: "2", Name: "CVE-2020-0001", FixedInVersion: "1.0.3"},
		},
		PackageVulnerabilities: map[string][]string{"1": {"2"}},
	}, []claircore.Digest{layer})

	var buf bytes.Buffer
	w := bufferWriteCloser{&buf}
	f, err := newTextFormatter(w)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Format(&Result{Name: "image", Report: r}); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"openssl", "1.0.2", "CVE-2020-0001", "layer:0 " + layer.String()} {
		if !strings.Contains(out, want) {
			t.Fatalf("output %q missing %q", out, want)
		}
	}
}
