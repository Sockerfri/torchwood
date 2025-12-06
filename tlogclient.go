package torchwood

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"iter"
	"log/slog"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/mod/sumdb/tlog"
	"golang.org/x/sync/errgroup"
)

// Client is a tlog client that fetches and authenticates tiles, and exposes log
// entries as a Go iterator or by their index.
type Client struct {
	tr      TileReader
	cut     func([]byte) ([]byte, tlog.Hash, []byte, error)
	timeout time.Duration
	err     error
}

// NewClient creates a new [Client] that fetches tiles using the given
// [TileReader]. The TileReader would typically be a [TileFetcher],
// optionally wrapped in a [PermanentCache] to cache tiles on disk.
func NewClient(tr TileReader, opts ...ClientOption) (*Client, error) {
	c := &Client{tr: tr}
	for _, opt := range opts {
		opt(c)
	}
	if c.cut == nil {
		c.cut = func(tile []byte) (entry []byte, rh tlog.Hash, rest []byte, err error) {
			entry, rest, err = ReadTileEntry(tile)
			return entry, tlog.RecordHash(entry), rest, err
		}
	}
	if c.timeout == 0 {
		c.timeout = 5 * time.Minute
	}
	return c, nil
}

// ClientOption is a function that configures a [Client].
type ClientOption func(*Client)

// WithTimeout configures the maximum duration the [Client.Entries] loop will
// block waiting for each next extry. The default is 5 minutes.
func WithTimeout(d time.Duration) ClientOption {
	return func(c *Client) {
		c.timeout = d
	}
}

// WithCutEntry configures the function to split the next entry from a data tile
// (a.k.a. entry bundle).
//
// The entry is surfaced by the Entries method, the record hash is used to check
// inclusion in the tree, and the rest is passed to the next invocation of cut.
//
// The input tile is never empty. cut must not modify the tile.
//
// By default, the c2sp.org/tlog-tiles#log-entries format is used, as
// implemented by [ReadTileEntry]. For the go.dev/design/25530-sumdb format, use
// [ReadSumDBEntry]. For the c2sp.org/static-ct-api format, use
// [filippo.io/sunlight.Client] instead.
func WithCutEntry(cut func(tile []byte) (entry []byte, rh tlog.Hash, rest []byte, err error)) ClientOption {
	return func(c *Client) {
		c.cut = cut
	}
}

// ReadSumDBEntry splits the next entry from a tile according to the
// go.dev/design/25530-sumdb format, for use with [WithCutEntry].
func ReadSumDBEntry(tile []byte) (entry []byte, rh tlog.Hash, rest []byte, err error) {
	if idx := bytes.Index(tile, []byte("\n\n")); idx >= 0 {
		// Add back one of the newlines.
		entry, rest = tile[:idx+1], tile[idx+2:]
	} else {
		entry, rest = tile, nil
	}
	return entry, tlog.RecordHash(entry), rest, nil
}

// WithSumDBEntries configures the function to split the next entry from a tile
// according to the go.dev/design/25530-sumdb format.
//
// Deprecated: use [WithCutEntry] with [ReadSumDBEntry] instead.
//
//go:fix inline
func WithSumDBEntries() ClientOption {
	return WithCutEntry(ReadSumDBEntry)
}

// Err returns the error encountered by the latest [Client.Entries] call.
func (c *Client) Err() error {
	return c.err
}

// Entries returns an iterator that yields entries from the given tree, starting
// at the given index. The first item in the yielded pair is the overall entry
// index in the log, starting at start.
//
// The provided tree should have been verified by the caller, for example by
// verifying the signatures on a [Checkpoint].
//
// Iteration may stop before the size of the tree to avoid fetching a partial
// data tile. Resuming with the same tree will yield the remaining entries,
// however clients tailing a growing log are encouraged to fetch the next
// checkpoint and use that as the tree argument. If this behavior is not
// desired, use [Client.AllEntries] instead.
//
// Callers must check [Client.Err] after the iteration breaks.
func (c *Client) Entries(ctx context.Context, tree tlog.Tree, start int64) iter.Seq2[int64, []byte] {
	c.err = nil
	mainCtx := ctx
	tr := &edgeMemoryCache{tr: c.tr, t: make(map[int][2]tileWithData)}
	return func(yield func(int64, []byte) bool) {
		ctx, cancel := context.WithTimeout(mainCtx, c.timeout)
		defer func() { cancel() }()
		for {
			if err := ctx.Err(); err != nil {
				c.err = err
				return
			}

			base := start / TileWidth * TileWidth
			// In regular operations, don't actually fetch the trailing partial
			// tile, to avoid duplicating that traffic in steady state. The
			// assumption is that a future call to Entries will pass a bigger
			// tree where that tile is full. However, if the tree grows too
			// slowly, we'll get another call where start is at the beginning of
			// the partial tile; in that case, fetch it.
			top := tree.N / TileWidth * TileWidth
			if top-base == 0 {
				top = tree.N
			}
			tiles := make([]tlog.Tile, 0, 50)
			for i := 0; i < 50; i++ {
				tileStart := base + int64(i)*TileWidth
				if tileStart >= top {
					break
				}
				tileEnd := tileStart + TileWidth
				if tileEnd > top {
					tileEnd = top
				}
				tiles = append(tiles, tlog.Tile{H: TileHeight, L: -1,
					N: tileStart / TileWidth, W: int(tileEnd - tileStart)})
			}
			if len(tiles) == 0 {
				return
			}
			tdata, err := tr.ReadTiles(ctx, tiles)
			if err != nil {
				c.err = err
				return
			}

			// TODO: hash data tile directly against level 8 hash.
			indexes := make([]int64, 0, TileWidth*len(tiles))
			for _, t := range tiles {
				for i := range t.W {
					indexes = append(indexes, tlog.StoredHashIndex(0, t.N*TileWidth+int64(i)))
				}
			}
			hashes, err := TileHashReaderWithContext(ctx, tree, tr).ReadHashes(indexes)
			if err != nil {
				c.err = err
				return
			}

			for ti, t := range tiles {
				tileStart := t.N * TileWidth
				tileEnd := tileStart + int64(t.W)
				data := tdata[ti]
				for i := tileStart; i < tileEnd; i++ {
					if err := ctx.Err(); err != nil {
						c.err = err
						return
					}

					if len(data) == 0 {
						c.err = fmt.Errorf("unexpected end of tile data for tile %d", t.N)
						return
					}

					entry, rh, rest, err := c.cut(data)
					if err != nil {
						c.err = fmt.Errorf("failed to cut entry %d: %w", i, err)
						return
					}
					data = rest

					if rh != hashes[i-base] {
						c.err = fmt.Errorf("hash mismatch for entry %d", i)
						return
					}

					if i < start {
						continue
					}
					if !yield(i, entry) {
						return
					}
					cancel()
					ctx, cancel = context.WithTimeout(mainCtx, c.timeout)
					_ = cancel // https://go.dev/issue/25720
				}
				if len(data) != 0 {
					c.err = fmt.Errorf("unexpected leftover data in tile %d", t.N)
					return
				}
				start = tileEnd
			}

			tr.SaveTiles(tiles, tdata)

			if start == top {
				return
			}
		}
	}
}

// AllEntries works like [Client.Entries], but fetches all entries up to the
// size of the tree, including those in partial data tiles.
//
// Callers that are tailing a growing log should instead use [Client.Entries],
// and fetch a new tree every time iteration stops.
func (c *Client) AllEntries(ctx context.Context, tree tlog.Tree, start int64) iter.Seq2[int64, []byte] {
	return func(yield func(int64, []byte) bool) {
		for i, entry := range c.Entries(ctx, tree, start) {
			if !yield(i, entry) {
				return
			}
			start = i + 1
		}
		if c.Err() == nil && start < tree.N && ctx.Err() == nil {
			for i, entry := range c.Entries(ctx, tree, start) {
				if !yield(i, entry) {
					return
				}
			}
		}
	}
}

type tileWithData struct {
	tlog.Tile
	data []byte
}

// edgeMemoryCache is a [TileReader] that caches two edges in the tree: the
// rightmost one that's used to compute the tree hash, and the one that moves
// through the tree as we progress through entries.
type edgeMemoryCache struct {
	tr TileReader
	t  map[int][2]tileWithData // map[level][2]tileWithData
}

func (c *edgeMemoryCache) ReadTiles(ctx context.Context, tiles []tlog.Tile) (data [][]byte, err error) {
	data = make([][]byte, len(tiles))
	missing := make([]tlog.Tile, 0, len(tiles))
	for i, t := range tiles {
		if td := c.t[t.L]; td[0].Tile == t {
			data[i] = td[0].data
		} else if td[1].Tile == t {
			data[i] = td[1].data
		} else {
			missing = append(missing, t)
		}
	}
	if len(missing) == 0 {
		return data, nil
	}
	missingData, err := c.tr.ReadTiles(ctx, missing)
	if err != nil {
		return nil, err
	}
	for i := range data {
		if data[i] == nil {
			data[i] = missingData[0]
			missingData = missingData[1:]
		}
	}
	return data, nil
}

func (c *edgeMemoryCache) SaveTiles(tiles []tlog.Tile, data [][]byte) {
	ts, ds := make([]tlog.Tile, 0, len(tiles)), make([][]byte, 0, len(tiles))
	for i, t := range tiles {
		// If it's already in the memory cache, it was already saved by the
		// lower layer, as well.
		if td := c.t[t.L]; td[0].Tile == t || td[1].Tile == t {
			continue
		}
		ts = append(ts, t)
		ds = append(ds, data[i])
	}
	c.tr.SaveTiles(ts, ds)

	// Concretely, we just save the two rightmost observed tiles at each level,
	// which in practice during a scan will be the two edges.
	for i, t := range tiles {
		td, ok := c.t[t.L]
		switch {
		case !ok:
			c.t[t.L] = [2]tileWithData{{Tile: t, data: data[i]}}
		case td[0].Tile == t || td[1].Tile == t:
			// Already saved.
		case tileLess(td[0].Tile, t) && tileLess(td[0].Tile, td[1].Tile):
			c.t[t.L] = [2]tileWithData{{Tile: t, data: data[i]}, td[1]}
		case tileLess(td[1].Tile, t) && tileLess(td[1].Tile, td[0].Tile):
			c.t[t.L] = [2]tileWithData{td[0], {Tile: t, data: data[i]}}
		}
	}
}

func tileLess(a, b tlog.Tile) bool {
	// A zero tile is always less than any other tile.
	if a == (tlog.Tile{}) {
		return true
	}
	if b == (tlog.Tile{}) {
		return false
	}
	if a.L != b.L {
		panic("different levels")
	}
	return a.N < b.N || (a.N == b.N && a.W < b.W)
}

func (c *edgeMemoryCache) ReadEndpoint(ctx context.Context, path string) (data []byte, err error) {
	return c.tr.ReadEndpoint(ctx, path)
}

// Entry returns a log entry by its index, and an inclusion proof in the tree.
//
// The provided tree should have been verified by the caller, for example by
// verifying the signatures on a [Checkpoint].
func (c *Client) Entry(ctx context.Context, tree tlog.Tree, index int64) ([]byte, tlog.RecordProof, error) {
	if index < 0 || index >= tree.N {
		return nil, nil, fmt.Errorf("tlog: invalid index %d for tree of size %d", index, tree.N)
	}

	dataTile := tlog.Tile{H: TileHeight, L: -1, N: index / TileWidth, W: TileWidth}
	dataTile.W = min(dataTile.W, int(tree.N-dataTile.N*TileWidth))
	data, err := c.tr.ReadTiles(ctx, []tlog.Tile{dataTile})
	if err != nil {
		return nil, nil, fmt.Errorf("tlog: failed to read tile %s: %w", dataTile.Path(), err)
	}

	tile := data[0]
	var entry []byte
	var rh tlog.Hash
	for range index - dataTile.N*TileWidth + 1 {
		if len(tile) == 0 {
			return nil, nil, fmt.Errorf("tlog: no entry at index %d in tile %s", index, dataTile.Path())
		}
		entry, rh, tile, err = c.cut(tile)
		if err != nil {
			return nil, nil, fmt.Errorf("tlog: failed to cut entry %d from tile %s: %w", index, dataTile.Path(), err)
		}
	}

	proof, err := tlog.ProveRecord(tree.N, index, TileHashReaderWithContext(ctx, tree, c.tr))
	if err != nil {
		return nil, nil, fmt.Errorf("tlog: failed to prove entry %d in tree of size %d: %w", index, tree.N, err)
	}
	if err := tlog.CheckRecord(proof, tree.N, tree.Hash, index, rh); err != nil {
		return nil, nil, fmt.Errorf("tlog: data entry %d does not match Merkle tree: %w", index, err)
	}

	return entry, proof, nil
}

// TileFetcher is a [TileReader] that fetches tiles from a remote server.
type TileFetcher struct {
	base     string
	hc       *http.Client
	ua       string
	log      *slog.Logger
	limit    int
	tilePath func(tlog.Tile) string
}

// NewTileFetcher creates a new [TileFetcher] that fetches tiles from the given
// base URL. By default, it fetches tiles according to c2sp.org/tlog-tiles.
func NewTileFetcher(base string, opts ...TileFetcherOption) (*TileFetcher, error) {
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}

	tf := &TileFetcher{base: base}
	for _, opt := range opts {
		opt(tf)
	}
	if tf.tilePath == nil {
		tf.tilePath = TilePath
	}
	if tf.hc == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.MaxIdleConnsPerHost = transport.MaxIdleConns
		tf.hc = &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		}
	}
	if tf.ua == "" {
		tf.ua = "filippo.io/torchwood.Client"
	}
	if tf.log == nil {
		tf.log = slog.New(slogDiscardHandler{})
	}

	return tf, nil
}

// TileFetcherOption is a function that configures a [TileFetcher].
type TileFetcherOption func(*TileFetcher)

// WithTileFetcherLogger configures the logger used by the TileFetcher.
// By default, log lines are discarded.
func WithTileFetcherLogger(log *slog.Logger) TileFetcherOption {
	return func(f *TileFetcher) {
		f.log = log
	}
}

// WithHTTPClient configures the HTTP client used by the TileFetcher.
//
// Note that TileFetcher may need to make multiple parallel requests to
// the same host, more than the default MaxIdleConnsPerHost.
func WithHTTPClient(hc *http.Client) TileFetcherOption {
	return func(f *TileFetcher) {
		f.hc = hc
	}
}

// WithUserAgent configures the User-Agent header used by the TileFetcher.
// By default, the User-Agent is "filippo.io/torchwood.Client".
func WithUserAgent(ua string) TileFetcherOption {
	return func(f *TileFetcher) {
		f.ua = ua
	}
}

// WithConcurrencyLimit configures the maximum number of concurrent requests
// made by the TileFetcher. By default, there is no limit.
func WithConcurrencyLimit(limit int) TileFetcherOption {
	return func(f *TileFetcher) {
		f.limit = limit
	}
}

// WithTilePath configures the function used to generate the tile path from a
// [tlog.Tile]. By default, TileFetcher uses the c2sp.org/tlog-tiles scheme
// implemented by [TilePath]. For the go.dev/design/25530-sumdb scheme, use
// [tlog.Tile.Path]. For the c2sp.org/static-ct-api scheme, use
// [filippo.io/sunlight.TilePath].
func WithTilePath(tilePath func(tlog.Tile) string) TileFetcherOption {
	return func(f *TileFetcher) {
		f.tilePath = tilePath
	}
}

// ReadTiles implements [TileReader].
//
// It retries 429 and 5xx responses, and network errors.
func (f *TileFetcher) ReadTiles(ctx context.Context, tiles []tlog.Tile) (data [][]byte, err error) {
	data = make([][]byte, len(tiles))
	errGroup, ctx := errgroup.WithContext(ctx)
	if f.limit > 0 {
		errGroup.SetLimit(f.limit)
	}
	for i, t := range tiles {
		errGroup.Go(func() error {
			if t.H != TileHeight {
				return fmt.Errorf("unexpected tile height %d", t.H)
			}
			path := f.tilePath(t)
			d, err := f.ReadEndpoint(ctx, path)
			data[i] = d
			return err
		})
	}
	return data, errGroup.Wait()
}

// ReadEndpoint fetches an arbitrary path.
//
// It retries 429 and 5xx responses, and network errors.
func (f *TileFetcher) ReadEndpoint(ctx context.Context, path string) (data []byte, err error) {
	req, err := http.NewRequestWithContext(ctx, "GET", f.base+path, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create request: %w", path, err)
	}
	var errs error
	var retryAfter time.Time
	for j := range 5 {
		if j > 0 {
			// Wait 1s, 5s, 25s, or 125s before retrying.
			pause := time.Duration(math.Pow(5, float64(j-1))) * time.Second
			if !retryAfter.IsZero() {
				pause = time.Until(retryAfter)
				retryAfter = time.Time{}
			}
			f.log.InfoContext(ctx, "retrying GET request", "path", path,
				"pause", pause, "errs", errs, "retry", j)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(pause):
			}
		}
		req.Header.Set("User-Agent", f.ua)
		resp, err := f.hc.Do(req)
		if err != nil {
			errs = errors.Join(errs, err)
			continue
		}
		defer resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
			retryAfter = parseRetryAfter(resp.Header.Get("Retry-After"))
			errs = errors.Join(errs, fmt.Errorf("unexpected status code %d", resp.StatusCode))
			continue
		case resp.StatusCode != http.StatusOK:
			return nil, fmt.Errorf("%s: unexpected status code %d", path, resp.StatusCode)
		}
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			errs = errors.Join(errs, err)
			continue
		}
		f.log.InfoContext(ctx, "fetched resource", "path", path, "size", len(data))
		return data, nil
	}
	return nil, fmt.Errorf("%s: %w", path, errs)
}

// parseRetryAfter parses the Retry-After header value. It returns the time
// to wait before retrying the request. If the header is not present or
// invalid, it returns zero.
func parseRetryAfter(header string) time.Time {
	if header == "" {
		return time.Time{}
	}
	n, err := strconv.Atoi(header)
	if err == nil {
		return time.Now().Add(time.Duration(n) * time.Second)
	}
	t, err := http.ParseTime(header)
	if err == nil {
		return t
	}
	return time.Time{}
}

// SaveTiles implements [TileReader]. It does nothing.
func (f *TileFetcher) SaveTiles(tiles []tlog.Tile, data [][]byte) {}

type slogDiscardHandler struct{}

func (slogDiscardHandler) Enabled(context.Context, slog.Level) bool  { return false }
func (slogDiscardHandler) Handle(context.Context, slog.Record) error { return nil }
func (slogDiscardHandler) WithAttrs(attrs []slog.Attr) slog.Handler  { return slogDiscardHandler{} }
func (slogDiscardHandler) WithGroup(name string) slog.Handler        { return slogDiscardHandler{} }

// PermanentCache is a [TileReader] that caches verified, non-partial tiles in a
// filesystem directory. It passes through ReadEndpoint calls without caching.
type PermanentCache struct {
	tr       TileReader
	dir      string
	log      *slog.Logger
	tilePath func(tlog.Tile) string
}

// NewPermanentCache creates a new [PermanentCache] that caches tiles in the
// given directory. The directory must exist.
func NewPermanentCache(tr TileReader, dir string, opts ...PermanentCacheOption) (*PermanentCache, error) {
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("cache directory %q does not exist or is not a directory: %w", dir, err)
	}
	c := &PermanentCache{tr: tr, dir: dir}
	for _, opt := range opts {
		opt(c)
	}
	if c.log == nil {
		c.log = slog.New(slogDiscardHandler{})
	}
	if c.tilePath == nil {
		c.tilePath = TilePath
	}
	return c, nil
}

// PermanentCacheOption is a function that configures a [PermanentCache].
type PermanentCacheOption func(*PermanentCache)

// WithPermanentCacheLogger configures the logger used by the PermanentCache.
// By default, log lines are discarded.
func WithPermanentCacheLogger(log *slog.Logger) PermanentCacheOption {
	return func(c *PermanentCache) {
		c.log = log
	}
}

// WithPermanentCacheTilePath configures the function used to generate the tile
// path from a [tlog.Tile]. By default, PermanentCache uses the
// c2sp.org/tlog-tiles scheme implemented by [TilePath]. For the
// go.dev/design/25530-sumdb scheme, use [tlog.Tile.Path]. For the
// c2sp.org/static-ct-api scheme, use [filippo.io/sunlight.TilePath].
func WithPermanentCacheTilePath(tilePath func(tlog.Tile) string) PermanentCacheOption {
	return func(f *PermanentCache) {
		f.tilePath = tilePath
	}
}

// ReadTiles implements [TileReader].
func (c *PermanentCache) ReadTiles(ctx context.Context, tiles []tlog.Tile) (data [][]byte, err error) {
	data = make([][]byte, len(tiles))
	missing := make([]tlog.Tile, 0, len(tiles))
	for i, t := range tiles {
		if t.H != TileHeight {
			return nil, fmt.Errorf("unexpected tile height %d", t.H)
		}
		path := filepath.Join(c.dir, c.tilePath(t))
		if d, err := os.ReadFile(path); errors.Is(err, os.ErrNotExist) {
			missing = append(missing, t)
		} else if err != nil {
			return nil, err
		} else {
			c.log.Info("loaded tile from cache", "path", c.tilePath(t), "size", len(d))
			data[i] = d
		}
	}
	if len(missing) == 0 {
		return data, nil
	}
	missingData, err := c.tr.ReadTiles(ctx, missing)
	if err != nil {
		return nil, err
	}
	for i := range data {
		if data[i] == nil {
			data[i] = missingData[0]
			missingData = missingData[1:]
		}
	}
	return data, nil
}

// SaveTiles implements [TileReader].
func (c *PermanentCache) SaveTiles(tiles []tlog.Tile, data [][]byte) {
	for i, t := range tiles {
		if t.H != TileHeight {
			c.log.Error("unexpected tile height", "tile", t, "height", t.H)
			continue
		}
		if t.W != TileWidth {
			continue // skip partial tiles
		}
		path := filepath.Join(c.dir, c.tilePath(t))
		if _, err := os.Stat(path); err == nil {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			c.log.Error("failed to create directory", "path", path, "error", err)
			return
		}
		if err := os.WriteFile(path, data[i], 0600); err != nil {
			c.log.Error("failed to write file", "path", path, "error", err)
		} else {
			c.log.Info("saved tile to cache", "path", c.tilePath(t), "size", len(data[i]))
		}
	}
	c.tr.SaveTiles(tiles, data)
}

// ReadEndpoint passes through to the underlying TileReader.
func (c *PermanentCache) ReadEndpoint(ctx context.Context, path string) (data []byte, err error) {
	return c.tr.ReadEndpoint(ctx, path)
}

// TileFS is a [TileReader] that reads tiles from a [fs.FS].
type TileFS struct {
	fs       fs.FS
	tilePath func(tlog.Tile) string
	gzip     bool
}

// NewTileFS creates a new [TileFS] that reads tiles from the given [fs.FS].
// By default, it expects tiles to be laid out according to c2sp.org/tlog-tiles.
func NewTileFS(f fs.FS, opts ...TileFSOption) (*TileFS, error) {
	tf := &TileFS{fs: f}
	for _, opt := range opts {
		opt(tf)
	}
	if tf.tilePath == nil {
		tf.tilePath = TilePath
	}
	return tf, nil
}

// TileFSOption is a function that configures a [TileFS].
type TileFSOption func(*TileFS)

// WithTileFSTilePath configures the function used to generate the tile path
// from a [tlog.Tile]. By default, TileFS uses the c2sp.org/tlog-tiles scheme
// implemented by [TilePath]. For the go.dev/design/25530-sumdb scheme, use
// [tlog.Tile.Path]. For the c2sp.org/static-ct-api scheme, use
// [filippo.io/sunlight.TilePath].
func WithTileFSTilePath(tilePath func(tlog.Tile) string) TileFSOption {
	return func(f *TileFS) {
		f.tilePath = tilePath
	}
}

// WithGzipDataTiles configures the TileFS to transparently decompress
// gzip-compressed data tiles.
func WithGzipDataTiles() TileFSOption {
	return func(f *TileFS) {
		f.gzip = true
	}
}

// ReadTiles implements [TileReader].
func (f *TileFS) ReadTiles(ctx context.Context, tiles []tlog.Tile) (data [][]byte, err error) {
	data = make([][]byte, len(tiles))
	for i, t := range tiles {
		if t.H != TileHeight {
			return nil, fmt.Errorf("unexpected tile height %d", t.H)
		}
		path := f.tilePath(t)
		d, err := fs.ReadFile(f.fs, path)
		if err != nil {
			return nil, fmt.Errorf("failed to read tile %s: %w", path, err)
		}
		if f.gzip && t.L == -1 {
			gr, err := gzip.NewReader(bytes.NewReader(d))
			if err != nil {
				return nil, fmt.Errorf("failed to create gzip reader for tile %s: %w", path, err)
			}
			decompressed, err := io.ReadAll(gr)
			if err != nil {
				return nil, fmt.Errorf("failed to decompress tile %s: %w", path, err)
			}
			if err := gr.Close(); err != nil {
				return nil, fmt.Errorf("failed to close gzip reader for tile %s: %w", path, err)
			}
			d = decompressed
		}
		data[i] = d
	}
	return data, nil
}

// ReadEndpoint fetches an arbitrary path.
func (f *TileFS) ReadEndpoint(ctx context.Context, path string) (data []byte, err error) {
	// Callers should use [os.Root] as a more robust protection, and FS
	// implementations should check ValidPath, but avoid the most trivial
	// directory traversal here as well.
	if !fs.ValidPath(path) {
		return nil, fmt.Errorf("invalid path %q", path)
	}
	return fs.ReadFile(f.fs, path)
}

// SaveTiles implements [TileReader]. It does nothing.
func (f *TileFS) SaveTiles(tiles []tlog.Tile, data [][]byte) {}

// TileArchiveFS is an [fs.FS] that reads tiles and accessory files from a
// collection of zip files, numbered 000.zip, 001.zip, ...
//
// Each zip file contains the corresponding level 2 tile, and all the full tiles
// below it. All other files (higher-level tiles, partial tiles on the right
// edge, checkpoint, etc.) are expected to be present in every zip file.
//
// It supports both c2sp.org/tlog-tiles and c2sp.org/static-ct-api tile layouts,
// but not go.dev/design/25530-sumdb.
//
// See also https://github.com/geomys/ct-archive/blob/main/README.md#archival-format.
type TileArchiveFS struct {
	zips fs.FS

	// cachedReader, if not nil, is the cachedIndex-th zip file.
	cachedReader *zip.Reader
	cachedFile   fs.File
	cachedIndex  int
}

// NewTileArchiveFS creates a new [TileArchiveFS] that reads zip files from
// the root of the given [fs.FS]. f.Open must return files that implement
// [io.ReaderAt].
func NewTileArchiveFS(f fs.FS) *TileArchiveFS {
	return &TileArchiveFS{zips: f}
}

// Open implements [fs.FS].
func (tf *TileArchiveFS) Open(name string) (fs.File, error) {
	var zipIndex int
	t, ok := parseMultiTilePath(name)
	switch {
	case !ok || t.L > 2 || t.W != TileWidth:
		// All zip files contain this file, so use the cached one, if any.
		zipIndex = tf.cachedIndex
	case t.L == 2:
		zipIndex = int(t.N)
	case t.L == 1:
		zipIndex = int(t.N / TileWidth)
	default: // levels 0 and -1
		zipIndex = int(t.N / (TileWidth * TileWidth))
	}
	zr, err := tf.zipReader(zipIndex)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}
	f, err := zr.Open(name)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fmt.Errorf("reading from %03d.zip: %w", zipIndex, err)}
	}
	return f, nil
}

func parseMultiTilePath(path string) (tlog.Tile, bool) {
	// Convert c2sp.org/static-ct-api to c2sp.org/tlog-tiles.
	if rest, ok := strings.CutPrefix(path, "tile/data/"); ok {
		path = "tile/entries/" + rest
	}
	tile, err := ParseTilePath(path)
	if err != nil {
		return tlog.Tile{}, false
	}
	return tile, true
}

func (tf *TileArchiveFS) zipReader(index int) (*zip.Reader, error) {
	if tf.cachedReader != nil && tf.cachedIndex == index {
		return tf.cachedReader, nil
	}
	if tf.cachedFile != nil {
		if err := tf.cachedFile.Close(); err != nil {
			return nil, fmt.Errorf("failed to close previous zip file: %w", err)
		}
	}
	zipPath := fmt.Sprintf("%03d.zip", index)
	f, err := tf.zips.Open(zipPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open zip file: %w", err)
	}
	at, ok := f.(io.ReaderAt)
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: zipPath, Err: errors.New("zip file does not implement io.ReaderAt")}
	}
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat zip file %q: %w", zipPath, err)
	}
	zr, err := zip.NewReader(at, fi.Size())
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: zipPath, Err: fmt.Errorf("failed to read zip file: %w", err)}
	}
	tf.cachedReader = zr
	tf.cachedFile = f
	tf.cachedIndex = index
	return zr, nil
}

func (tf *TileArchiveFS) Close() error {
	if tf.cachedFile != nil {
		err := tf.cachedFile.Close()
		tf.cachedReader = nil
		tf.cachedFile = nil
		tf.cachedIndex = 0
		return err
	}
	return nil
}
