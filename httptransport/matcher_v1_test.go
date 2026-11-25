package httptransport

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/quay/claircore"
	indexerController "github.com/quay/claircore/indexer/controller"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/test"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/quay/clair/v4/indexer"
	"github.com/quay/clair/v4/internal/httputil"
	"github.com/quay/clair/v4/layerreport"
	"github.com/quay/clair/v4/matcher"
)

// TestUpdateDiffHandler is a parallel harness for testing a UpdateDiff handler.
func TestUpdateDiffHandler(t *testing.T) {
	t.Run("Matcher", testUpdateDiffMatcher)
	t.Run("Params", testUpdateDiffHandlerParams)
	t.Run("Methods", testUpdateDiffHandlerMethods)
}

// TestUpdateDiffMatcher confirms the UpdateDiff handler provides
// the correct status codes when a matcher returns an error or success
func testUpdateDiffMatcher(t *testing.T) {
	ctx := test.Logging(t)
	t.Parallel()
	mOK := &matcher.Mock{
		UpdateDiff_: func(context.Context, uuid.UUID, uuid.UUID) (*driver.UpdateDiff, error) {
			return nil, nil
		},
	}
	hOK := NewMatcherV1(ctx, "", mOK, &indexer.Mock{}, time.Second*10, otelhttp.WithTracerProvider(noop.NewTracerProvider()))
	mErr := &matcher.Mock{
		UpdateDiff_: func(context.Context, uuid.UUID, uuid.UUID) (*driver.UpdateDiff, error) {
			return nil, fmt.Errorf("expected error")
		},
	}
	hErr := NewMatcherV1(ctx, "", mErr, &indexer.Mock{}, time.Second*10, otelhttp.WithTracerProvider(noop.NewTracerProvider()))

	srvOK := httptest.NewUnstartedServer(hOK)
	srvOK.Config.BaseContext = func(_ net.Listener) context.Context { return ctx }
	srvOK.Start()
	defer srvOK.Close()

	srvErr := httptest.NewUnstartedServer(hErr)
	srvErr.Config.BaseContext = func(_ net.Listener) context.Context { return ctx }
	srvErr.Start()
	defer srvErr.Close()

	// test matcher returns nil error
	url, err := url.Parse(srvOK.URL)
	if err != nil {
		t.Fatalf("failed to parse test server URL into *net/URL")
	}
	url.Path = path.Join("/", "internal", "update_diff")
	q := url.Query()
	q.Set("cur", "892737b2-a616-4113-a7a9-137139c8f91e")
	url.RawQuery = q.Encode()
	t.Log(url)

	req, err := httputil.NewRequestWithContext(ctx, http.MethodGet, url.String(), nil)
	if err != nil {
		t.Fatalf("failed to construct request: %v", err)
	}
	resp, err := srvOK.Client().Do(req)
	if err != nil {
		t.Fatalf("failed to do request: %v", err)
	}
	defer resp.Body.Close()
	got, want := resp.StatusCode, http.StatusOK
	if got != want {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Log("could not read body of unexpected response")
		}
		t.Logf("unexpected response body: %s", string(body))
		t.Fatalf("got: %v, want: %v", got, want)
	}

	// test matcher returns error
	url, err = url.Parse(srvErr.URL)
	if err != nil {
		t.Fatalf("failed to parse test server URL into *net/URL")
	}
	url.Path = path.Join("/", "internal", "update_diff")
	q = url.Query()
	q.Set("cur", "892737b2-a616-4113-a7a9-137139c8f91e")
	url.RawQuery = q.Encode()
	t.Log(url)

	req, err = httputil.NewRequestWithContext(ctx, http.MethodGet, url.String(), nil)
	if err != nil {
		t.Fatalf("failed to construct request: %v", err)
	}
	resp, err = srvErr.Client().Do(req)
	if err != nil {
		t.Fatalf("failed to do request: %v", err)
	}
	got, want = resp.StatusCode, http.StatusInternalServerError
	if got != want {
		t.Fatalf("got: %v, want: %v", got, want)
	}
}

// TestUpdateDiffHandlerParams confirms the UpdateDiff handler
// returns correct status codes given a set or url parameters
func testUpdateDiffHandlerParams(t *testing.T) {
	ctx := test.Logging(t)
	t.Parallel()
	table := []struct {
		name       string
		cur        string
		prev       string
		statusCode int
	}{
		{
			name:       "no params",
			cur:        "",
			prev:       "",
			statusCode: http.StatusBadRequest,
		},
		{
			name:       "missing prev",
			cur:        "892737b2-a616-4113-a7a9-137139c8f91e",
			prev:       "",
			statusCode: http.StatusOK,
		},
		{
			name:       "missing cur",
			cur:        "",
			prev:       "892737b2-a616-4113-a7a9-137139c8f91e",
			statusCode: http.StatusBadRequest,
		},
		{
			name:       "all params",
			cur:        "6ea97b35-d886-4845-8ba2-5a4b0a074bfe",
			prev:       "892737b2-a616-4113-a7a9-137139c8f91e",
			statusCode: http.StatusOK,
		},
	}

	mOK := &matcher.Mock{
		UpdateDiff_: func(context.Context, uuid.UUID, uuid.UUID) (*driver.UpdateDiff, error) {
			return nil, nil
		},
	}
	h := NewMatcherV1(ctx, "", mOK, &indexer.Mock{}, time.Second*10, otelhttp.WithTracerProvider(noop.NewTracerProvider()))
	srv := httptest.NewUnstartedServer(h)
	srv.Config.BaseContext = func(_ net.Listener) context.Context { return ctx }
	srv.Start()
	defer srv.Close()

	c := srv.Client()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("failed to parse test server URL into *net/URL")
	}
	u.Path = path.Join("/", "internal", "update_diff")

	for _, test := range table {
		t.Run(test.name, func(t *testing.T) {
			q := u.Query()
			q.Set("cur", test.cur)
			q.Set("prev", test.cur)
			u.RawQuery = q.Encode()

			req, err := httputil.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
			if err != nil {
				t.Fatalf("failed to construct request: %v", err)
			}
			resp, err := c.Do(req)
			if err != nil {
				t.Fatalf("failed to do request: %v", err)
			}
			got, want := resp.StatusCode, test.statusCode
			if got != want {
				t.Fatalf("got: %v, want: %v", got, want)
			}
		})
	}
}

// TestUpdateDiffHandlerMethods confirms the UpdateDiffHandler responds correctly
// to unaccepted HTTP methods.
func testUpdateDiffHandlerMethods(t *testing.T) {
	ctx := test.Logging(t)
	t.Parallel()
	mOK := &matcher.Mock{
		UpdateDiff_: func(context.Context, uuid.UUID, uuid.UUID) (*driver.UpdateDiff, error) {
			return nil, nil
		},
	}
	h := NewMatcherV1(ctx, "", mOK, &indexer.Mock{}, time.Second*10, otelhttp.WithTracerProvider(noop.NewTracerProvider()))
	srv := httptest.NewUnstartedServer(h)
	srv.Config.BaseContext = func(_ net.Listener) context.Context { return ctx }
	srv.Start()
	defer srv.Close()

	c := srv.Client()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("failed to parse test server URL into *net/URL")
	}
	u.Path = path.Join("/", "internal", "update_diff")

	for _, m := range []string{
		http.MethodConnect,
		http.MethodHead,
		http.MethodOptions,
		http.MethodPatch,
		http.MethodPost,
		http.MethodPut,
		http.MethodTrace,
	} {
		req, err := httputil.NewRequestWithContext(ctx, m, u.String(), nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("method: %v got: %v want: %v", m, resp.Status, http.StatusMethodNotAllowed)
		}
	}
}

// TestUpdateOperationHandler is a parallel harness for testing a UpdateOperation handler.
func TestUpdateOperationHandler(t *testing.T) {
	t.Run("Methods", testUpdateOperationHandlerMethods)
	t.Run("GetAndDelete", testUpdateOperationHandlerGet)
	t.Run("Errors", testUpdateOperationHandlerErrors)
}

// testUpdateOperationHandlerErrors confirms the handler perfoms the correct
// actions when a matcher.Differ is failing.
func testUpdateOperationHandlerErrors(t *testing.T) {
	ctx := test.Logging(t)
	t.Parallel()

	id := uuid.New().String()
	ErrExpected := fmt.Errorf("expected error")
	m := &matcher.Mock{
		DeleteUpdateOperations_: func(context.Context, ...uuid.UUID) (int64, error) { return 0, ErrExpected },
		// this will not immediately fail the handler
		LatestUpdateOperation_: func(context.Context, driver.UpdateKind) (uuid.UUID, error) {
			return uuid.Nil, ErrExpected
		},
		LatestUpdateOperations_: func(context.Context, driver.UpdateKind) (map[string][]driver.UpdateOperation, error) {
			return nil, ErrExpected
		},
		UpdateOperations_: func(context.Context, driver.UpdateKind, ...string) (map[string][]driver.UpdateOperation, error) {
			return nil, ErrExpected
		},
	}
	h := NewMatcherV1(ctx, "", m, &indexer.Mock{}, time.Second*10, otelhttp.WithTracerProvider(noop.NewTracerProvider()))
	srv := httptest.NewUnstartedServer(h)
	srv.Config.BaseContext = func(_ net.Listener) context.Context { return ctx }
	srv.Start()
	defer srv.Close()
	c := srv.Client()

	// perform get with failing differ
	req, err := httputil.NewRequestWithContext(ctx, http.MethodGet, srv.URL+path.Join("/", "internal", "update_operation"), nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("got: %v, want: %v", resp.StatusCode, http.StatusInternalServerError)
	}

	// perform delete with failing differ
	u := srv.URL + path.Join("/", "internal", "update_operation") + "/" + id
	req, err = httputil.NewRequestWithContext(ctx, http.MethodDelete, u, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	resp, err = c.Do(req)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("got: %v, want: %v", resp.StatusCode, http.StatusInternalServerError)
	}
}

// testUpdateOperationHandlerMethods confirms the handler only responds
// to the desired methods.
func testUpdateOperationHandlerMethods(t *testing.T) {
	ctx := test.Logging(t)
	t.Parallel()
	h := NewMatcherV1(ctx, "", &matcher.Mock{}, &indexer.Mock{}, time.Second*10, otelhttp.WithTracerProvider(noop.NewTracerProvider()))
	srv := httptest.NewUnstartedServer(h)
	srv.Config.BaseContext = func(_ net.Listener) context.Context { return ctx }
	srv.Start()
	defer srv.Close()
	c := srv.Client()

	for _, m := range []string{
		http.MethodConnect,
		http.MethodHead,
		http.MethodOptions,
		http.MethodPatch,
		http.MethodPost,
		http.MethodPut,
		http.MethodTrace,
	} {
		req, err := httputil.NewRequestWithContext(ctx, m, srv.URL+path.Join("/", "internal", "update_operation"), nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("failed to make request: %v", err)
		}
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("method: %v got: %v want: %v", m, resp.Status, http.StatusMethodNotAllowed)
		}
	}
}

// testUpdateOperationHandlerGet confirms the handler performs the correct
// actions on GET.
func testUpdateOperationHandlerGet(t *testing.T) {
	ctx := test.Logging(t)
	t.Parallel()

	id := uuid.New()
	idStr := "\"" + id.String() + "\""
	var called bool
	var latestCalled bool
	m := &matcher.Mock{
		LatestUpdateOperation_: func(context.Context, driver.UpdateKind) (uuid.UUID, error) {
			return id, nil
		},
		LatestUpdateOperations_: func(context.Context, driver.UpdateKind) (map[string][]driver.UpdateOperation, error) {
			latestCalled = true
			return nil, nil
		},
		UpdateOperations_: func(context.Context, driver.UpdateKind, ...string) (map[string][]driver.UpdateOperation, error) {
			called = true
			return nil, nil
		},
	}
	h := NewMatcherV1(ctx, "", m, &indexer.Mock{}, time.Second*10, otelhttp.WithTracerProvider(noop.NewTracerProvider()))
	srv := httptest.NewUnstartedServer(h)
	srv.Config.BaseContext = func(_ net.Listener) context.Context { return ctx }
	srv.Start()
	defer srv.Close()
	c := srv.Client()

	// get without latest param
	req, err := httputil.NewRequestWithContext(ctx, http.MethodGet, srv.URL+path.Join("/", "internal", "update_operation"), nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got: %v, want: %v", resp.StatusCode, http.StatusOK)
	}
	if !called {
		t.Fatalf("got: %v, want: %v", called, true)
	}
	etag := resp.Header.Get("etag")
	if etag != idStr {
		t.Fatalf("got: %v, want: %v", etag, id.String())
	}

	// get with latest param
	u, _ := url.Parse(srv.URL)
	u.Path = path.Join("/", "internal", "update_operation")
	q := u.Query()
	q.Add("latest", "true")
	u.RawQuery = q.Encode()

	req, err = httputil.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	resp, err = c.Do(req)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got: %v, want: %v", resp.StatusCode, http.StatusOK)
	}
	if !latestCalled {
		t.Fatalf("got: %v, want: %v", latestCalled, true)
	}
	etag = resp.Header.Get("etag")
	if etag != idStr {
		t.Fatalf("got: %v, want: %v", etag, id.String())
	}
}

func TestVulnerabilityReportLayerAttribution(t *testing.T) {
	ctx := test.Logging(t)
	l0, err := claircore.ParseDigest("sha256:" + fmt.Sprintf("%064d", 0))
	if err != nil {
		t.Fatal(err)
	}
	l1, err := claircore.ParseDigest("sha256:" + fmt.Sprintf("%064d", 1))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := claircore.ParseDigest("sha256:" + fmt.Sprintf("%064d", 2))
	if err != nil {
		t.Fatal(err)
	}

	vr := &claircore.VulnerabilityReport{
		Hash: manifest,
		Packages: map[string]*claircore.Package{
			"openssl": {ID: "openssl", Name: "openssl", Version: "1.0.2"},
			"curl":    {ID: "curl", Name: "curl", Version: "7.1"},
		},
		Environments: map[string][]*claircore.Environment{
			"openssl": {{IntroducedIn: l0}},
			"curl":    {{IntroducedIn: l1}},
		},
		Vulnerabilities: map[string]*claircore.Vulnerability{
			"CVE-1": {ID: "CVE-1", Name: "CVE-2020-0001"},
			"CVE-2": {ID: "CVE-2", Name: "CVE-2020-0002"},
		},
		PackageVulnerabilities: map[string][]string{
			"openssl": {"CVE-1"},
			"curl":    {"CVE-2"},
		},
	}
	i := &indexer.Mock{
		IndexReport_: func(context.Context, claircore.Digest) (*claircore.IndexReport, bool, error) {
			return &claircore.IndexReport{State: indexerController.IndexFinished.String()}, true, nil
		},
		ManifestLayers_: func(context.Context, claircore.Digest) ([]claircore.Digest, error) {
			return []claircore.Digest{l0, l1}, nil
		},
	}
	m := &matcher.Mock{
		Initialized_: func(context.Context) (bool, error) { return true, nil },
		Scan_: func(context.Context, *claircore.IndexReport) (*claircore.VulnerabilityReport, error) {
			return vr, nil
		},
	}
	h := NewMatcherV1(ctx, "", m, i, time.Second, otelhttp.WithTracerProvider(noop.NewTracerProvider()))
	srv := httptest.NewServer(h)
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = path.Join("/", "vulnerability_report", manifest.String())

	bodies := make([][]byte, 2)
	for n := range bodies {
		resp, err := srv.Client().Get(u.String())
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("got status %d, body: %s", resp.StatusCode, body)
		}
		bodies[n] = body
	}
	if string(bodies[0]) != string(bodies[1]) {
		t.Fatalf("repeated report requests differ:\nfirst: %s\nsecond: %s", bodies[0], bodies[1])
	}

	var got layerreport.Report
	if err := json.Unmarshal(bodies[0], &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Layers) != 2 {
		t.Fatalf("got %d layers, want 2", len(got.Layers))
	}
	if got.Layers[0].Hash.String() != l0.String() || got.Layers[1].Hash.String() != l1.String() {
		t.Fatalf("layers are not in image order: %v", got.Layers)
	}
	if got.PackageLayers["openssl"] != l0.String() || got.PackageLayers["curl"] != l1.String() {
		t.Fatalf("unexpected package attribution: %v", got.PackageLayers)
	}
	if got.LayerVulnerabilities[l0.String()][0] != "CVE-1" {
		t.Fatalf("unexpected layer vulnerability attribution: %v", got.LayerVulnerabilities)
	}
	if p := got.Layers[0].Packages[0]; p.Name != "openssl" || p.Version != "1.0.2" {
		t.Fatalf("unexpected package version mapping: %+v", p)
	}

	// Existing consumers must still see all of the old top-level fields.
	var legacy map[string]json.RawMessage
	if err := json.Unmarshal(bodies[0], &legacy); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{
		"manifest_hash", "packages", "distributions", "environments",
		"vulnerabilities", "package_vulnerabilities", "repository",
	} {
		if _, ok := legacy[k]; !ok {
			t.Fatalf("legacy field %q missing from response", k)
		}
	}
}
