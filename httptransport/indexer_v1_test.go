package httptransport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/claircore/pkg/tarfs"
	"github.com/quay/claircore/test"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/quay/clair/v4/indexer"
	"github.com/quay/clair/v4/internal/httputil"
)

func TestManifestLayers(t *testing.T) {
	ctx := test.Logging(t)
	digest := claircore.MustParseDigest("sha256:0000000000000000000000000000000000000000000000000000000000000000")
	layer := claircore.MustParseDigest("sha256:1111111111111111111111111111111111111111111111111111111111111111")
	i := &indexer.Mock{
		ManifestLayers_: func(_ context.Context, d claircore.Digest) ([]claircore.Digest, error) {
			if d.String() != digest.String() {
				t.Fatalf("got digest %s, want %s", d, digest)
			}
			return []claircore.Digest{layer}, nil
		},
	}
	v1, err := NewIndexerV1(ctx, "", i, otelhttp.WithTracerProvider(noop.NewTracerProvider()))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(v1)
	defer srv.Close()

	res, err := srv.Client().Get(srv.URL + "/layers/" + digest.String())
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if got, want := res.StatusCode, http.StatusOK; got != want {
		t.Fatalf("got status %d, want %d", got, want)
	}
	var got struct {
		ManifestHash claircore.Digest   `json:"manifest_hash"`
		Layers       []claircore.Digest `json:"layers"`
	}
	if err := json.NewDecoder(res.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.ManifestHash.String() != digest.String() {
		t.Fatalf("got manifest %s, want %s", got.ManifestHash, digest)
	}
	if len(got.Layers) != 1 || got.Layers[0].String() != layer.String() {
		t.Fatalf("got layers %v, want [%s]", got.Layers, layer)
	}
}

func TestIndexReportBadLayer(t *testing.T) {
	ctx := test.Logging(t)

	i := &indexer.Mock{
		State_: func(ctx context.Context) (string, error) {
			return `deadbeef`, nil
		},
		Index_: func(ctx context.Context, m *claircore.Manifest) (*claircore.IndexReport, error) {
			return nil, tarfs.ErrFormat
		},
	}
	v1, err := NewIndexerV1(ctx, "", i, otelhttp.WithTracerProvider(noop.NewTracerProvider()))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(v1)
	srv.Config.BaseContext = func(_ net.Listener) context.Context { return ctx }
	srv.Start()
	defer srv.Close()
	t.Run("Report", func(t *testing.T) {
		ctx := test.Logging(t, ctx)
		const path = `/index_report`
		t.Run("POST", func(t *testing.T) {
			const body = `{"hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000",` +
				`"layers":[{}]}`
			req, err := httputil.NewRequestWithContext(ctx, http.MethodPost, srv.URL+path, strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			res, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			got, want := res.StatusCode, http.StatusBadRequest
			t.Logf("got: %d, want: %d", got, want)
			if got != want {
				t.Error()
			}
		})
	})
}

func TestIndexerV1(t *testing.T) {
	ctx := test.Logging(t)

	digest := claircore.MustParseDigest("sha256:0000000000000000000000000000000000000000000000000000000000000000")
	i := &indexer.Mock{
		State_: func(ctx context.Context) (string, error) {
			return `deadbeef`, nil
		},
		DeleteManifests_: func(_ context.Context, ds ...claircore.Digest) ([]claircore.Digest, error) {
			for _, d := range ds {
				if got, want := d.String(), digest.String(); got != want {
					return nil, fmt.Errorf("unexpected digest: %v", d)
				}
			}
			return ds, nil
		},
		Index_: func(ctx context.Context, m *claircore.Manifest) (*claircore.IndexReport, error) {
			return new(claircore.IndexReport), nil
		},
		IndexReport_: func(_ context.Context, d claircore.Digest) (*claircore.IndexReport, bool, error) {
			if got, want := d.String(), digest.String(); got != want {
				return nil, false, fmt.Errorf("unexpected digest: %v", d)
			}
			return new(claircore.IndexReport), true, nil
		},
		AffectedManifests_: func(_ context.Context, _ []claircore.Vulnerability) (*claircore.AffectedManifests, error) {
			return new(claircore.AffectedManifests), nil
		},
	}

	v1, err := NewIndexerV1(ctx, "", i, otelhttp.WithTracerProvider(noop.NewTracerProvider()))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(v1)
	srv.Config.BaseContext = func(_ net.Listener) context.Context { return ctx }
	srv.Start()
	defer srv.Close()

	t.Run("State", func(t *testing.T) {
		ctx := test.Logging(t, ctx)
		const path = `/index_state`
		t.Run("GET", func(t *testing.T) {
			req, err := httputil.NewRequestWithContext(ctx, http.MethodGet, srv.URL+path, nil)
			if err != nil {
				t.Fatal(err)
			}
			res, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			got, want := res.StatusCode, http.StatusOK
			t.Logf("got: %d, want: %d", got, want)
			if got != want {
				t.Error()
			}
		})
	})
	t.Run("Report", func(t *testing.T) {
		ctx := test.Logging(t, ctx)
		const path = `/index_report`
		t.Run("POST", func(t *testing.T) {
			const body = `{"hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000",` +
				`"layers":[{}]}`
			req, err := httputil.NewRequestWithContext(ctx, http.MethodPost, srv.URL+path, strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			res, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			got, want := res.StatusCode, http.StatusCreated
			t.Logf("got: %d, want: %d", got, want)
			if got != want {
				t.Error()
			}
		})
		t.Run("DELETE", func(t *testing.T) {
			const body = `["sha256:0000000000000000000000000000000000000000000000000000000000000000"]`
			req, err := httputil.NewRequestWithContext(ctx, http.MethodDelete, srv.URL+path, strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			res, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			var buf bytes.Buffer
			got, want := res.StatusCode, http.StatusOK
			t.Logf("got: %d, want: %d", got, want)
			if got != want {
				t.Error()
			}
			if _, err := io.Copy(&buf, res.Body); err != nil {
				t.Error(err)
			}
			// Should get back what we put in, so this is a little hack.
			if got, want := buf.String(), body; got != want {
				t.Errorf("got: %q, want: %q", got, want)
			}
		})
		t.Run("GET", func(t *testing.T) {
			req, err := httputil.NewRequestWithContext(ctx, http.MethodGet, srv.URL+path, nil)
			if err != nil {
				t.Fatal(err)
			}
			res, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			got, want := res.StatusCode, http.StatusMethodNotAllowed
			t.Logf("got: %d, want: %d", got, want)
			if got != want {
				t.Error()
			}
		})
	})
	t.Run("ReportOne", func(t *testing.T) {
		ctx := test.Logging(t, ctx)
		const path = `/index_report/sha256:0000000000000000000000000000000000000000000000000000000000000000`
		t.Run("DELETE", func(t *testing.T) {
			req, err := httputil.NewRequestWithContext(ctx, http.MethodDelete, srv.URL+path, nil)
			if err != nil {
				t.Fatal(err)
			}
			res, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			got, want := res.StatusCode, http.StatusNoContent
			t.Logf("got: %d, want: %d", got, want)
			if got != want {
				t.Error()
			}
		})
		t.Run("GET", func(t *testing.T) {
			req, err := httputil.NewRequestWithContext(ctx, http.MethodGet, srv.URL+path, nil)
			if err != nil {
				t.Fatal(err)
			}
			res, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			got, want := res.StatusCode, http.StatusOK
			t.Logf("got: %d, want: %d", got, want)
			if got != want {
				t.Error()
			}
		})
	})
	t.Run("AffectedManifests", func(t *testing.T) {
		ctx := test.Logging(t, ctx)
		const path = `/internal/affected_manifest/`
		t.Run("POST", func(t *testing.T) {
			const body = `{"vulnerabilities":[]}`
			req, err := httputil.NewRequestWithContext(ctx, http.MethodPost, srv.URL+path, strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			res, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			got, want := res.StatusCode, http.StatusOK
			t.Logf("got: %d, want: %d", got, want)
			if got != want {
				t.Error()
			}
		})
	})
}
