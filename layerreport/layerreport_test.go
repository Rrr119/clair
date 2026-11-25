package layerreport_test

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/quay/claircore"

	"github.com/quay/clair/v4/internal/codec"
	"github.com/quay/clair/v4/layerreport"
)

func digest(t *testing.T, n byte) claircore.Digest {
	t.Helper()
	d, err := claircore.ParseDigest(fmt.Sprintf("sha256:%s", strings.Repeat(fmt.Sprintf("%02x", n), 32)))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func pkg(id, name, version string) *claircore.Package {
	return &claircore.Package{ID: id, Name: name, Version: version}
}

func vuln(id, name string) *claircore.Vulnerability {
	return &claircore.Vulnerability{ID: id, Name: name}
}

func report(t *testing.T, layers []claircore.Digest, pkgs map[string]*claircore.Package, envs map[string]claircore.Digest, vulns map[string]*claircore.Vulnerability, pkgVulns map[string][]string) *claircore.VulnerabilityReport {
	t.Helper()
	d, err := claircore.ParseDigest("sha256:" + strings.Repeat("11", 32))
	if err != nil {
		t.Fatal(err)
	}
	vr := &claircore.VulnerabilityReport{
		Hash:                   d,
		Packages:               pkgs,
		Environments:           map[string][]*claircore.Environment{},
		Vulnerabilities:        vulns,
		PackageVulnerabilities: pkgVulns,
	}
	for id, layer := range envs {
		vr.Environments[id] = []*claircore.Environment{{IntroducedIn: layer}}
	}
	return vr
}

func TestThreeImages(t *testing.T) {
	l0, l1, l2, l3, l4, l5 := digest(t, 0x10), digest(t, 0x11), digest(t, 0x12), digest(t, 0x13), digest(t, 0x14), digest(t, 0x15)
	cves := map[string]*claircore.Vulnerability{
		"CVE-1": vuln("CVE-1", "CVE-2020-0001"),
		"CVE-2": vuln("CVE-2", "CVE-2020-0002"),
		"CVE-3": vuln("CVE-3", "CVE-2020-0003"),
		"CVE-4": vuln("CVE-4", "CVE-2020-0004"),
	}

	tests := []struct {
		name   string
		layers []claircore.Digest
		vr     *claircore.VulnerabilityReport
		want   map[string]struct {
			index   int
			hash    claircore.Digest
			pkg     string
			version string
		}
	}{
		{
			name:   "debian",
			layers: []claircore.Digest{l0, l1, l2},
			vr: report(t, nil,
				map[string]*claircore.Package{
					"openssl": pkg("openssl", "openssl", "1.0.2"),
					"curl":    pkg("curl", "curl", "7.1"),
				},
				map[string]claircore.Digest{"openssl": l0, "curl": l1},
				cves,
				map[string][]string{"openssl": {"CVE-1"}, "curl": {"CVE-2"}},
			),
			want: map[string]struct {
				index   int
				hash    claircore.Digest
				pkg     string
				version string
			}{
				"CVE-1": {0, l0, "openssl", "1.0.2"},
				"CVE-2": {1, l1, "curl", "7.1"},
			},
		},
		{
			name:   "alpine",
			layers: []claircore.Digest{l0, l3},
			vr: report(t, nil,
				map[string]*claircore.Package{
					"openssl": pkg("openssl", "openssl", "1.0.2"),
					"busybox": pkg("busybox", "busybox", "1.2"),
				},
				map[string]claircore.Digest{"openssl": l0, "busybox": l3},
				cves,
				map[string][]string{"openssl": {"CVE-1"}, "busybox": {"CVE-3"}},
			),
			want: map[string]struct {
				index   int
				hash    claircore.Digest
				pkg     string
				version string
			}{
				"CVE-1": {0, l0, "openssl", "1.0.2"},
				"CVE-3": {1, l3, "busybox", "1.2"},
			},
		},
		{
			name:   "python",
			layers: []claircore.Digest{l4, l5},
			vr: report(t, nil,
				map[string]*claircore.Package{
					"python": pkg("python", "python", "3.8"),
				},
				map[string]claircore.Digest{"python": l4},
				cves,
				map[string][]string{"python": {"CVE-4"}},
			),
			want: map[string]struct {
				index   int
				hash    claircore.Digest
				pkg     string
				version string
			}{
				"CVE-4": {0, l4, "python", "3.8"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := layerreport.Build(tc.vr, tc.layers)
			for vulnID, want := range tc.want {
				layerHash := got.PackageLayers[want.pkg]
				if layerHash != want.hash.String() {
					t.Fatalf("%s: package %s attributed to %q, want %q", vulnID, want.pkg, layerHash, want.hash)
				}
				layer := got.Layers[want.index]
				if layer.Hash.String() != want.hash.String() {
					t.Fatalf("%s: layer index %d is %s, want %s", vulnID, want.index, layer.Hash, want.hash)
				}
				var foundPkg, foundVuln bool
				for _, p := range layer.Packages {
					if p.Name == want.pkg && p.Version == want.version {
						foundPkg = true
					}
				}
				for _, v := range layer.Vulnerabilities {
					if v.ID == vulnID {
						foundVuln = true
					}
				}
				if !foundPkg || !foundVuln {
					t.Fatalf("%s: layer %s missing package %s@%s (pkg=%v vuln=%v)",
						vulnID, layer.Hash, want.pkg, want.version, foundPkg, foundVuln)
				}
			}
		})
	}
}

func TestStable(t *testing.T) {
	l0, l1 := digest(t, 0x20), digest(t, 0x21)
	vr := report(t, nil,
		map[string]*claircore.Package{
			"b": pkg("b", "zlib", "1.2"),
			"a": pkg("a", "openssl", "1.1"),
		},
		map[string]claircore.Digest{"a": l0, "b": l1},
		map[string]*claircore.Vulnerability{
			"v1": vuln("v1", "CVE-2021-0001"),
			"v2": vuln("v2", "CVE-2021-0002"),
		},
		map[string][]string{"a": {"v2", "v1"}, "b": {"v1"}},
	)

	first := layerreport.Build(vr, []claircore.Digest{l0, l1})
	var want bytes.Buffer
	enc := codec.GetEncoder(&want)
	if err := enc.Encode(first); err != nil {
		t.Fatal(err)
	}
	codec.PutEncoder(enc)

	for i := 0; i < 100; i++ {
		got := layerreport.Build(vr, []claircore.Digest{l0, l1})
		if !reflect.DeepEqual(first, got) {
			t.Fatalf("iteration %d: attribution is not stable", i)
		}
		var b bytes.Buffer
		enc := codec.GetEncoder(&b)
		if err := enc.Encode(got); err != nil {
			t.Fatal(err)
		}
		codec.PutEncoder(enc)
		if !bytes.Equal(want.Bytes(), b.Bytes()) {
			t.Fatalf("iteration %d: encoded report is not stable\nfirst: %s\ngot:   %s", i, want.Bytes(), b.Bytes())
		}
	}

	if _, ok := first.PackageLayers["a"]; !ok {
		t.Fatal("package a has no layer attribution")
	}
	if _, ok := first.LayerVulnerabilities[l0.String()]; !ok {
		t.Fatal("layer 0 has no vulnerability attribution")
	}
	if got := first.VulnerabilityLayers["v1"]; len(got) != 2 {
		t.Fatalf("v1 attributed to %v, want 2 layers", got)
	}
}

func TestFallbackOrder(t *testing.T) {
	a, b, c := digest(t, 0x30), digest(t, 0x31), digest(t, 0x32)
	vr := report(t, nil,
		map[string]*claircore.Package{
			"p1": pkg("p1", "a", "1"),
			"p2": pkg("p2", "b", "1"),
			"p3": pkg("p3", "c", "1"),
		},
		map[string]claircore.Digest{"p1": c, "p2": a, "p3": b},
		map[string]*claircore.Vulnerability{"v": vuln("v", "CVE-2022-0001")},
		map[string][]string{"p1": {"v"}, "p2": {"v"}, "p3": {"v"}},
	)
	got := layerreport.Build(vr, nil)
	if len(got.Layers) != 3 {
		t.Fatalf("got %d layers, want 3", len(got.Layers))
	}
	if got.Layers[0].Hash.String() != a.String() ||
		got.Layers[1].Hash.String() != b.String() ||
		got.Layers[2].Hash.String() != c.String() {
		t.Fatalf("layers not digest-ordered: %v %v %v", got.Layers[0].Hash, got.Layers[1].Hash, got.Layers[2].Hash)
	}
}

func TestCoreCompatibility(t *testing.T) {
	layer := digest(t, 0x40)
	vr := report(t, nil,
		map[string]*claircore.Package{
			"openssl": pkg("openssl", "openssl", "1.0.2"),
		},
		map[string]claircore.Digest{"openssl": layer},
		map[string]*claircore.Vulnerability{"CVE-1": vuln("CVE-1", "CVE-2020-0001")},
		map[string][]string{"openssl": {"CVE-1"}},
	)
	got := layerreport.Build(vr, []claircore.Digest{layer})

	var buf bytes.Buffer
	enc := codec.GetEncoder(&buf)
	if err := enc.Encode(got); err != nil {
		t.Fatal(err)
	}
	codec.PutEncoder(enc)

	var legacy claircore.VulnerabilityReport
	dec := codec.GetDecoder(bytes.NewReader(buf.Bytes()))
	err := dec.Decode(&legacy)
	codec.PutDecoder(dec)
	if err != nil {
		t.Fatal(err)
	}
	if p := legacy.Packages["openssl"]; p == nil || p.Name != "openssl" || p.Version != "1.0.2" {
		t.Fatalf("legacy decode lost package: %+v", p)
	}
	if v := legacy.PackageVulnerabilities["openssl"]; len(v) != 1 || v[0] != "CVE-1" {
		t.Fatalf("legacy decode lost package vulnerabilities: %v", v)
	}

	var full layerreport.Report
	dec = codec.GetDecoder(bytes.NewReader(buf.Bytes()))
	err = dec.Decode(&full)
	codec.PutDecoder(dec)
	if err != nil {
		t.Fatal(err)
	}
	if len(full.Layers) != 1 || full.Layers[0].Hash.String() != layer.String() {
		t.Fatalf("full decode lost layers: %+v", full.Layers)
	}
	if p := full.Layers[0].Packages[0]; p.Name != "openssl" || p.Version != "1.0.2" {
		t.Fatalf("full decode lost layer package: %+v", p)
	}
}
