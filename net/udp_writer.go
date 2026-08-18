package net

import (
	"context"
	"maps"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/33TU/socks/internal"
)

// Defaults for AsyncUDPWriter, applied when a field is left zero.
const (
	DefaultUDPWriterQueueSize   = 256
	DefaultUDPWriterWorkers     = 4
	DefaultUDPWriterCacheTTL    = 60 * time.Second
	DefaultUDPWriterCacheSize   = 1024
	DefaultUDPWriterResolveWait = 5 * time.Second
)

// AsyncUDPWriter sends datagrams to domain targets without blocking its caller.
//
// A UDP relay reads every session's packets from one socket, so resolving a
// domain on that goroutine stalls all traffic for the length of the lookup, and
// a slow or unreachable resolver stalls it for the length of the timeout. This
// writer moves resolution onto a small pool of workers, caching results so that
// a domain seen before is written immediately and never queued at all.
//
// Datagrams are dropped rather than queued without bound, which is what a UDP
// relay should do under overload.
type AsyncUDPWriter struct {
	conn     net.PacketConn
	resolver *net.Resolver

	// OnError receives resolution and write failures. It may be nil.
	onError func(error)

	queue chan udpWriteItem
	wg    sync.WaitGroup

	// ctx is cancelled by Close, which aborts lookups already in flight so that
	// closing never waits out a stalled resolver.
	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
	done      chan struct{}

	cacheTTL  time.Duration
	cacheSize int

	// cache is replaced wholesale rather than mutated, so a lookup is an
	// atomic load and a map read with no lock at all. Reads happen per
	// datagram; writes only when a name is resolved, once per TTL.
	cache atomic.Pointer[map[udpCacheKey]udpCacheEntry]

	// storeMu serializes the copy-on-write updates, not the readers.
	storeMu sync.Mutex
}

// udpCacheKey names a resolved target. The port is part of the key so the
// address object can be cached whole and reused without allocating.
type udpCacheKey struct {
	domain string
	port   uint16
}

// AsyncUDPWriterConfig configures an AsyncUDPWriter.
type AsyncUDPWriterConfig struct {
	// Resolver resolves domain targets. Nil means net.DefaultResolver.
	Resolver *net.Resolver

	// QueueSize bounds how many datagrams may await resolution.
	// Zero means DefaultUDPWriterQueueSize.
	QueueSize int

	// Workers is how many resolutions may be in flight at once.
	// Zero means DefaultUDPWriterWorkers.
	Workers int

	// CacheTTL is how long a resolved address is reused.
	// Zero means DefaultUDPWriterCacheTTL.
	CacheTTL time.Duration

	// CacheSize bounds the number of cached domains.
	// Zero means DefaultUDPWriterCacheSize.
	CacheSize int

	// OnError receives resolution and write failures. It may be nil.
	OnError func(error)
}

type udpWriteItem struct {
	payload *internal.Buffer // from the byte pool, released once sent
	domain  string
	port    uint16
}

type udpCacheEntry struct {
	addr    *net.UDPAddr
	expires time.Time
}

// NewAsyncUDPWriter starts a writer sending on conn.
// Close must be called to release its workers.
func NewAsyncUDPWriter(conn net.PacketConn, cfg *AsyncUDPWriterConfig) *AsyncUDPWriter {
	if cfg == nil {
		cfg = &AsyncUDPWriterConfig{}
	}

	ctx, cancel := context.WithCancel(context.Background())

	w := &AsyncUDPWriter{
		ctx:       ctx,
		cancel:    cancel,
		conn:      conn,
		resolver:  cfg.Resolver,
		onError:   cfg.OnError,
		done:      make(chan struct{}),
		cacheTTL:  cfg.CacheTTL,
		cacheSize: cfg.CacheSize,
	}

	empty := make(map[udpCacheKey]udpCacheEntry)
	w.cache.Store(&empty)

	if w.resolver == nil {
		w.resolver = net.DefaultResolver
	}
	if w.cacheTTL <= 0 {
		w.cacheTTL = DefaultUDPWriterCacheTTL
	}
	if w.cacheSize <= 0 {
		w.cacheSize = DefaultUDPWriterCacheSize
	}

	queueSize := cfg.QueueSize
	if queueSize <= 0 {
		queueSize = DefaultUDPWriterQueueSize
	}
	w.queue = make(chan udpWriteItem, queueSize)

	workers := cfg.Workers
	if workers <= 0 {
		workers = DefaultUDPWriterWorkers
	}

	w.wg.Add(workers)
	for range workers {
		go w.work()
	}

	return w
}

// WriteToDomain sends payload to domain:port.
//
// A domain whose address is already cached is sent immediately, from the
// calling goroutine and without copying payload. Otherwise payload is copied
// and queued for a worker to resolve and send.
//
// It never blocks. It reports false when the datagram was dropped, either
// because the queue was full or the writer is closed.
func (w *AsyncUDPWriter) WriteToDomain(payload []byte, domain string, port uint16) bool {
	if addr, ok := w.lookupCache(domain, port); ok {
		w.send(payload, addr)
		return true
	}

	// The caller reuses its read buffer, so the payload has to be copied to
	// outlive this call.
	buf := internal.GetBuffer(len(payload))
	copy(buf.B, payload)

	select {
	case <-w.done:
		internal.PutBuffer(buf)
		return false
	default:
	}

	select {
	case w.queue <- udpWriteItem{payload: buf, domain: domain, port: port}:
		return true
	default:
		internal.PutBuffer(buf)
		return false
	}
}

// Close stops the writer's workers and releases any queued datagrams.
func (w *AsyncUDPWriter) Close() error {
	w.closeOnce.Do(func() {
		close(w.done)
		w.cancel()
		w.wg.Wait()

		// Anything queued by a caller racing this Close is released here.
		for {
			select {
			case item := <-w.queue:
				internal.PutBuffer(item.payload)
			default:
				return
			}
		}
	})

	return nil
}

// work resolves and sends queued datagrams.
func (w *AsyncUDPWriter) work() {
	defer w.wg.Done()

	for {
		select {
		case <-w.done:
			return
		case item := <-w.queue:
			// Both cases can be ready at once, and select picks at random, so
			// closing is checked again here rather than draining the queue.
			select {
			case <-w.done:
				internal.PutBuffer(item.payload)
				return
			default:
			}

			addr, err := w.resolve(item.domain, item.port)
			if err != nil {
				internal.PutBuffer(item.payload)
				w.reportError(err)
				continue
			}

			w.send(item.payload.B, addr)
			internal.PutBuffer(item.payload)
		}
	}
}

// resolve returns an address for domain:port, consulting the cache first.
func (w *AsyncUDPWriter) resolve(domain string, port uint16) (*net.UDPAddr, error) {
	if addr, ok := w.lookupCache(domain, port); ok {
		return addr, nil
	}

	ctx, cancel := context.WithTimeout(w.ctx, DefaultUDPWriterResolveWait)
	defer cancel()

	ips, err := w.resolver.LookupIP(ctx, "ip", domain)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, &net.DNSError{Err: "no addresses", Name: domain, IsNotFound: true}
	}

	return w.storeCache(domain, port, ips[0]), nil
}

func (w *AsyncUDPWriter) lookupCache(domain string, port uint16) (*net.UDPAddr, bool) {
	entry, ok := (*w.cache.Load())[udpCacheKey{domain: domain, port: port}]
	if !ok || time.Now().After(entry.expires) {
		return nil, false
	}
	return entry.addr, true
}

func (w *AsyncUDPWriter) storeCache(domain string, port uint16, ip net.IP) *net.UDPAddr {
	addr := &net.UDPAddr{IP: append(net.IP(nil), ip...), Port: int(port)}

	w.storeMu.Lock()
	defer w.storeMu.Unlock()

	current := *w.cache.Load()

	// Bounded, and cheapest to start over: entries are equivalent and
	// short-lived, so there is nothing worth choosing between them.
	next := make(map[udpCacheKey]udpCacheEntry, len(current)+1)
	if len(current) < w.cacheSize {
		maps.Copy(next, current)
	}

	next[udpCacheKey{domain: domain, port: port}] = udpCacheEntry{
		addr:    addr,
		expires: time.Now().Add(w.cacheTTL),
	}

	w.cache.Store(&next)
	return addr
}

func (w *AsyncUDPWriter) send(payload []byte, addr net.Addr) {
	if _, err := w.conn.WriteTo(payload, addr); err != nil {
		w.reportError(err)
	}
}

func (w *AsyncUDPWriter) reportError(err error) {
	if w.onError != nil {
		w.onError(err)
	}
}
