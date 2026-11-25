// Package layerreport provides per-layer vulnerability attribution for a
// vulnerability report.
package layerreport

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/quay/claircore"
)

// Report is a vulnerability report augmented with per-layer attribution.
//
// The fields mirror claircore.VulnerabilityReport so existing consumers can
// keep using the same names. The added fields make it possible to answer
// "which layer introduced this package, and therefore this vulnerability?"
// without changing the layout of existing fields.
type Report struct {
	// The manifest hash this vulnerability report is describing.
	ManifestHash claircore.Digest `json:"manifest_hash"`
	// All discovered packages keyed by package id.
	Packages map[string]*claircore.Package `json:"packages"`
	// All discovered distributions keyed by distribution id.
	Distributions map[string]*claircore.Distribution `json:"distributions"`
	// All discovered repositories keyed by repository id.
	Repositories map[string]*claircore.Repository `json:"repository"`
	// Environment details keyed by package id.
	Environments map[string][]*claircore.Environment `json:"environments"`
	// All discovered vulnerabilities keyed by vulnerability id.
	Vulnerabilities map[string]*claircore.Vulnerability `json:"vulnerabilities"`
	// PackageVulnerabilities records vulnerabilities by package id.
	PackageVulnerabilities map[string][]string `json:"package_vulnerabilities"`
	// Enrichments is a map keyed by enrichment type.
	Enrichments map[string][]json.RawMessage `json:"enrichments"`
	// PackageNotVulnerable records "not vulnerable" assertions.
	PackageNotVulnerable map[string][]string

	// Layers is ordered by the image's layer order when it is known, and by
	// layer digest otherwise.
	Layers []Layer `json:"layers"`
	// LayerPackages maps a layer digest to the identifiers of the packages
	// introduced by that layer. The package objects, including versions, are
	// available in the report's "packages" map and in Layer.Packages.
	LayerPackages map[string][]string `json:"layer_packages"`
	// LayerVulnerabilities maps a layer digest to the vulnerabilities
	// introduced by packages in that layer.
	LayerVulnerabilities map[string][]string `json:"layer_vulnerabilities"`
	// PackageLayers maps a package identifier to the layer that introduced the
	// package version.
	PackageLayers map[string]string `json:"package_layers"`
	// VulnerabilityLayers maps a vulnerability identifier to the layers whose
	// packages introduced it.
	VulnerabilityLayers map[string][]string `json:"vulnerability_layers"`
}

// Layer describes the packages and vulnerabilities attributed to one image
// layer.
type Layer struct {
	// Index is the layer's position in the image, starting at zero. When the
	// image's layer order is unavailable, Index is a stable, digest-sorted
	// position.
	Index int `json:"index"`
	// Hash is the content digest of the layer.
	Hash claircore.Digest `json:"hash"`
	// Packages are the packages introduced by this layer.
	Packages []*claircore.Package `json:"packages"`
	// Vulnerabilities are the vulnerabilities introduced by this layer.
	Vulnerabilities []*claircore.Vulnerability `json:"vulnerabilities"`
	// PackageVulnerabilities mirrors the top-level field for this layer.
	PackageVulnerabilities map[string][]string `json:"package_vulnerabilities"`
}

// LayerIndex returns the position of the layer with the provided digest, or
// -1 if it is not present.
func (r *Report) LayerIndex(hash string) int {
	for _, l := range r.Layers {
		if l.Hash.String() == hash {
			return l.Index
		}
	}
	return -1
}

// Build computes layer attribution for the provided vulnerability report.
//
// manifestLayers is the image's layer order. It can be nil when the caller
// cannot provide it; in that case, layers present in the report are ordered by
// digest so repeated scans produce identical results.
func Build(vr *claircore.VulnerabilityReport, manifestLayers []claircore.Digest) *Report {
	out := &Report{
		Layers:               []Layer{},
		LayerPackages:        map[string][]string{},
		LayerVulnerabilities: map[string][]string{},
		PackageLayers:        map[string]string{},
		VulnerabilityLayers:  map[string][]string{},
	}
	if vr == nil {
		return out
	}
	out.ManifestHash = vr.Hash
	out.Packages = vr.Packages
	out.Distributions = vr.Distributions
	out.Repositories = vr.Repositories
	out.Environments = sortedEnvironments(vr.Environments)
	out.Vulnerabilities = vr.Vulnerabilities
	out.PackageVulnerabilities = sortedPackageVulnerabilities(vr.PackageVulnerabilities, vr.Vulnerabilities)
	out.Enrichments = vr.Enrichments
	out.PackageNotVulnerable = vr.PackageNotVulnerable

	// Build the authoritative ordering. Duplicate digests are retained in the
	// layer list because an image may legally repeat a layer, but attribution
	// uses the first occurrence.
	layerIndex := make(map[string]int, len(manifestLayers))
	order := make([]claircore.Digest, 0, len(manifestLayers))
	for _, d := range manifestLayers {
		h := d.String()
		if h == "" {
			continue
		}
		if _, ok := layerIndex[h]; !ok {
			layerIndex[h] = len(order)
			order = append(order, d)
		}
	}

	type pkgAttribution struct {
		id    string
		pkg   *claircore.Package
		vulns []string
	}
	attributed := make(map[string][]*pkgAttribution)
	pkgIDs := allPackageIDs(vr)
	for _, id := range pkgIDs {
		pkg := vr.Packages[id]
		if pkg == nil {
			pkg = &claircore.Package{ID: id}
		}
		layer, ok := introductionLayer(vr.Environments[id], layerIndex)
		if !ok {
			continue
		}
		a := &pkgAttribution{
			id:    id,
			pkg:   pkg,
			vulns: sortedVulnerabilityIDs(vr.PackageVulnerabilities[id], vr.Vulnerabilities),
		}
		attributed[layer] = append(attributed[layer], a)
		out.PackageLayers[id] = layer
	}

	// If no manifest order was supplied, derive one from the layers that were
	// actually attributed. This keeps the fallback deterministic.
	if len(order) == 0 {
		hashes := make([]string, 0, len(attributed))
		for h := range attributed {
			hashes = append(hashes, h)
		}
		sort.Strings(hashes)
		for _, h := range hashes {
			d, err := claircore.ParseDigest(h)
			if err != nil {
				continue
			}
			layerIndex[h] = len(order)
			order = append(order, d)
		}
	} else {
		// Attributed layers should normally be present in manifestLayers. If
		// the index and vulnerability data disagree, append missing layers in
		// digest order so the attribution is still usable.
		var missing []string
		for h := range attributed {
			if _, ok := layerIndex[h]; !ok {
				missing = append(missing, h)
			}
		}
		sort.Strings(missing)
		for _, h := range missing {
			d, err := claircore.ParseDigest(h)
			if err != nil {
				continue
			}
			layerIndex[h] = len(order)
			order = append(order, d)
		}
	}

	layers := make([]Layer, len(order))
	for i, d := range order {
		layers[i] = Layer{
			Index:                  i,
			Hash:                   d,
			Packages:               []*claircore.Package{},
			Vulnerabilities:        []*claircore.Vulnerability{},
			PackageVulnerabilities: map[string][]string{},
		}
	}

	for i := range layers {
		h := layers[i].Hash.String()
		if _, ok := out.LayerPackages[h]; !ok {
			out.LayerPackages[h] = []string{}
		}
		if _, ok := out.LayerVulnerabilities[h]; !ok {
			out.LayerVulnerabilities[h] = []string{}
		}
		a := attributed[h]
		sort.Slice(a, func(i, j int) bool {
			pi, pj := a[i].pkg, a[j].pkg
			if pi.Name != pj.Name {
				return pi.Name < pj.Name
			}
			if pi.Version != pj.Version {
				return pi.Version < pj.Version
			}
			return a[i].id < a[j].id
		})

		seenVulns := make(map[string]struct{})
		for _, p := range a {
			layers[i].Packages = append(layers[i].Packages, p.pkg)
			layers[i].PackageVulnerabilities[p.id] = append([]string(nil), p.vulns...)
			out.LayerPackages[h] = append(out.LayerPackages[h], p.id)
			for _, id := range p.vulns {
				seenVulns[id] = struct{}{}
			}
		}
		for _, id := range sortedVulnerabilitySet(seenVulns, vr.Vulnerabilities) {
			v := vr.Vulnerabilities[id]
			if v == nil {
				v = &claircore.Vulnerability{ID: id}
			}
			layers[i].Vulnerabilities = append(layers[i].Vulnerabilities, v)
			out.LayerVulnerabilities[h] = append(out.LayerVulnerabilities[h], id)
			out.VulnerabilityLayers[id] = append(out.VulnerabilityLayers[id], h)
		}
	}

	out.Layers = layers
	return out
}

func introductionLayer(envs []*claircore.Environment, order map[string]int) (string, bool) {
	var candidates []string
	for _, env := range envs {
		if env == nil {
			continue
		}
		if h := env.IntroducedIn.String(); h != "" {
			candidates = append(candidates, h)
		}
	}
	if len(candidates) == 0 {
		return "", false
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		oi, iok := order[candidates[i]]
		oj, jok := order[candidates[j]]
		switch {
		case iok && jok && oi != oj:
			return oi < oj
		case iok != jok:
			return iok
		default:
			return candidates[i] < candidates[j]
		}
	})
	return candidates[0], true
}

func sortedEnvironments(envs map[string][]*claircore.Environment) map[string][]*claircore.Environment {
	if envs == nil {
		return nil
	}
	out := make(map[string][]*claircore.Environment, len(envs))
	for id, es := range envs {
		es = append([]*claircore.Environment(nil), es...)
		sort.SliceStable(es, func(i, j int) bool {
			a, b := es[i], es[j]
			switch {
			case a == nil && b == nil:
				return false
			case a == nil:
				return false
			case b == nil:
				return true
			}
			if a.IntroducedIn.String() != b.IntroducedIn.String() {
				return a.IntroducedIn.String() < b.IntroducedIn.String()
			}
			if a.PackageDB != b.PackageDB {
				return a.PackageDB < b.PackageDB
			}
			if a.DistributionID != b.DistributionID {
				return a.DistributionID < b.DistributionID
			}
			return strings.Join(a.RepositoryIDs, "\x00") < strings.Join(b.RepositoryIDs, "\x00")
		})
		out[id] = es
	}
	return out
}

func sortedPackageVulnerabilities(m map[string][]string, vulns map[string]*claircore.Vulnerability) map[string][]string {
	if m == nil {
		return nil
	}
	out := make(map[string][]string, len(m))
	for id, ids := range m {
		out[id] = sortedVulnerabilityIDs(ids, vulns)
	}
	return out
}

func allPackageIDs(vr *claircore.VulnerabilityReport) []string {
	ids := make(map[string]struct{})
	for id := range vr.Packages {
		ids[id] = struct{}{}
	}
	for id := range vr.Environments {
		ids[id] = struct{}{}
	}
	for id := range vr.PackageVulnerabilities {
		ids[id] = struct{}{}
	}
	out := make([]string, 0, len(ids))
	for id := range ids {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := vr.Packages[out[i]], vr.Packages[out[j]]
		switch {
		case a == nil && b == nil:
			return out[i] < out[j]
		case a == nil:
			return false
		case b == nil:
			return true
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		return out[i] < out[j]
	})
	return out
}

func sortedVulnerabilityIDs(ids []string, vulns map[string]*claircore.Vulnerability) []string {
	out := make([]string, 0, len(ids))
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return sortedVulnerabilitySet(seen, vulns)
}

func sortedVulnerabilitySet(ids map[string]struct{}, vulns map[string]*claircore.Vulnerability) []string {
	out := make([]string, 0, len(ids))
	for id := range ids {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := vulns[out[i]], vulns[out[j]]
		switch {
		case a == nil && b == nil:
			return out[i] < out[j]
		case a == nil:
			return false
		case b == nil:
			return true
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return out[i] < out[j]
	})
	return out
}
