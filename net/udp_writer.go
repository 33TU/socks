package net

import (
	"context"
	"net"
	"sync"
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

	mu    sync.RWMutex
	cache map[string]udpCacheEntry
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
	payload []byte // from the byte pool, released once sent
	domain  string
	port    uint16
}

type udpCacheEntry struct {
	ip      net.IP
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
		cache:     make(map[string]udpCacheEntry),
	}

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
	if ip, ok := w.lookupCache(domain); ok {
		w.send(payload, &net.UDPAddr{IP: ip, Port: int(port)})
		return true
	}

	// The caller reuses its read buffer, so the payload has to be copied to
	// outlive this call.
	buf := internal.GetBytes(len(payload))
	copy(buf, payload)

	select {
	case <-w.done:
		internal.PutBytes(buf)
		return false
	default:
	}

	select {
	case w.queue <- udpWriteItem{payload: buf, domain: domain, port: port}:
		return true
	default:
		internal.PutBytes(buf)
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
				internal.PutBytes(item.payload)
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
				internal.PutBytes(item.payload)
				return
			default:
			}

			ip, err := w.resolve(item.domain)
			if err != nil {
				internal.PutBytes(item.payload)
				w.reportError(err)
				continue
			}

			w.send(item.payload, &net.UDPAddr{IP: ip, Port: int(item.port)})
			internal.PutBytes(item.payload)
		}
	}
}

// resolve returns an address for domain, consulting the cache first.
func (w *AsyncUDPWriter) resolve(domain string) (net.IP, error) {
	if ip, ok := w.lookupCache(domain); ok {
		return ip, nil
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

	w.storeCache(domain, ips[0])
	return ips[0], nil
}

func (w *AsyncUDPWriter) lookupCache(domain string) (net.IP, bool) {
	w.mu.RLock()
	entry, ok := w.cache[domain]
	w.mu.RUnlock()

	if !ok || time.Now().After(entry.expires) {
		return nil, false
	}
	return entry.ip, true
}

func (w *AsyncUDPWriter) storeCache(domain string, ip net.IP) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Bounded, and cheapest to clear wholesale: entries are equivalent and
	// short-lived, so there is nothing worth choosing between them.
	if len(w.cache) >= w.cacheSize {
		clear(w.cache)
	}

	w.cache[domain] = udpCacheEntry{
		ip:      append(net.IP(nil), ip...),
		expires: time.Now().Add(w.cacheTTL),
	}
}

func (w *AsyncUDPWriter) send(payload []byte, addr *net.UDPAddr) {
	if _, err := w.conn.WriteTo(payload, addr); err != nil {
		w.reportError(err)
	}
}

func (w *AsyncUDPWriter) reportError(err error) {
	if w.onError != nil {
		w.onError(err)
	}
}
