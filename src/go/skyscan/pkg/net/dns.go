package net

import (
	"context"
	"net"
	"sync"
	"time"
)

// DNSResolver provides high-performance DNS resolution for bucket enumeration.
// DNS-based enumeration is stealthier than HTTP HEAD requests as it:
// 1. Doesn't trigger S3 access logging
// 2. Uses small UDP packets (faster than TCP/TLS handshakes)
// 3. Can check existence without authentication
type DNSResolver struct {
	resolvers []string
	timeout   time.Duration
	mu        sync.RWMutex
	cache     map[string]bool // Simple cache for resolved domains
}

// NewDNSResolver creates a resolver with custom DNS servers
func NewDNSResolver(resolvers []string, timeout int) *DNSResolver {
	if len(resolvers) == 0 {
		// Default to fast public resolvers
		resolvers = []string{
			"8.8.8.8:53",        // Google
			"1.1.1.1:53",        // Cloudflare
			"9.9.9.9:53",        // Quad9
			"208.67.222.222:53", // OpenDNS
		}
	}

	return &DNSResolver{
		resolvers: resolvers,
		timeout:   time.Duration(timeout) * time.Second,
		cache:     make(map[string]bool),
	}
}

// DNSResult represents the result of a DNS check
type DNSResult struct {
	Domain  string
	Exists  bool
	IPs     []string
	Error   error
	Latency time.Duration
}

// CheckExists performs a DNS lookup to check if a domain exists
// Returns true if the domain resolves (bucket exists), false if NXDOMAIN
func (r *DNSResolver) CheckExists(ctx context.Context, domain string) *DNSResult {
	// Check cache first
	r.mu.RLock()
	if exists, ok := r.cache[domain]; ok {
		r.mu.RUnlock()
		return &DNSResult{Domain: domain, Exists: exists}
	}
	r.mu.RUnlock()

	start := time.Now()

	// Create resolver with custom DNS server
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: r.timeout}
			// Rotate through resolvers
			server := r.resolvers[time.Now().UnixNano()%int64(len(r.resolvers))]
			return d.DialContext(ctx, "udp", server)
		},
	}

	// Set context timeout
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	// Perform lookup
	ips, err := resolver.LookupHost(ctx, domain)
	latency := time.Since(start)

	result := &DNSResult{
		Domain:  domain,
		Latency: latency,
	}

	if err != nil {
		// Check if it's NXDOMAIN (doesn't exist) vs other error
		if dnsErr, ok := err.(*net.DNSError); ok {
			if dnsErr.IsNotFound {
				result.Exists = false
				// Cache negative result
				r.mu.Lock()
				r.cache[domain] = false
				r.mu.Unlock()
				return result
			}
		}
		result.Error = err
		return result
	}

	// Domain resolves - bucket exists
	result.Exists = true
	result.IPs = ips

	// Cache positive result
	r.mu.Lock()
	r.cache[domain] = true
	r.mu.Unlock()

	return result
}

// BatchCheck performs concurrent DNS lookups for multiple domains
func (r *DNSResolver) BatchCheck(ctx context.Context, domains []string, concurrency int) []*DNSResult {
	results := make([]*DNSResult, len(domains))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i, domain := range domains {
		wg.Add(1)
		go func(idx int, d string) {
			defer wg.Done()

			// Acquire semaphore
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				results[idx] = &DNSResult{Domain: d, Error: ctx.Err()}
				return
			}
			defer func() { <-sem }()

			results[idx] = r.CheckExists(ctx, d)
		}(i, domain)
	}

	wg.Wait()
	return results
}

// ClearCache clears the DNS resolution cache
func (r *DNSResolver) ClearCache() {
	r.mu.Lock()
	r.cache = make(map[string]bool)
	r.mu.Unlock()
}
