package indexer

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/quay/claircore"
)

// PostgresIndexer wraps an indexer Service and can additionally report the
// ordered layers stored for a manifest.
type PostgresIndexer struct {
	Service
	pool *pgxpool.Pool
}

// NewPostgresIndexer wraps s and uses pool for manifest layer lookups.
func NewPostgresIndexer(s Service, pool *pgxpool.Pool) *PostgresIndexer {
	return &PostgresIndexer{
		Service: s,
		pool:    pool,
	}
}

var _ LayerReporter = (*PostgresIndexer)(nil)

// ManifestLayers returns the digest of each layer in the manifest, ordered from
// the base layer to the top layer.
func (p *PostgresIndexer) ManifestLayers(ctx context.Context, manifest claircore.Digest) ([]claircore.Digest, error) {
	if p.pool == nil {
		return nil, errors.New("indexer: nil database pool")
	}
	const query = `
SELECT l.hash
FROM manifest_layer AS ml
JOIN manifest AS m ON m.id = ml.manifest_id
JOIN layer AS l ON l.id = ml.layer_id
WHERE m.hash = $1
ORDER BY ml.i ASC;
`
	rows, err := p.pool.Query(ctx, query, manifest.String())
	if err != nil {
		return nil, fmt.Errorf("querying manifest layers: %w", err)
	}
	defer rows.Close()

	var out []claircore.Digest
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, fmt.Errorf("scanning manifest layer: %w", err)
		}
		d, err := claircore.ParseDigest(h)
		if err != nil {
			return nil, fmt.Errorf("parsing manifest layer digest %q: %w", h, err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating manifest layers: %w", err)
	}
	return out, nil
}
