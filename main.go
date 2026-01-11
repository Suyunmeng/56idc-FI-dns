package main

import (
	"github.com/miekg/dns"
	"log"
	"math/rand"
	"sync"
	"time"
)

var (
	// IPv6 upstreams (Google) for primary resolution
	googleIPv6Servers = []string{"[2001:4860:4860::8888]:53", "[2001:4860:4860::8844]:53"}
	// IPv4 upstreams (Cloudflare) for A record replacement
	cloudflareIPv4Servers = []string{"1.0.0.1:53", "1.1.1.1:53"}
	rng                   = rand.New(rand.NewSource(time.Now().UnixNano()))
	rngMu                 sync.Mutex
)

// DNS cache entry with expiration
type cacheEntry struct {
	response  *dns.Msg
	expiresAt time.Time
}

// DNS response cache with concurrent access support
type dnsCache struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry
}

func newDNSCache() *dnsCache {
	return &dnsCache{
		entries: make(map[string]*cacheEntry),
	}
}

// Get cached response if not expired
func (c *dnsCache) Get(key string) (*dns.Msg, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[key]
	if !exists {
		return nil, false
	}

	if time.Now().After(entry.expiresAt) {
		return nil, false
	}

	return entry.response.Copy(), true
}

// Set cache entry with TTL
func (c *dnsCache) Set(key string, resp *dns.Msg, ttl uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[key] = &cacheEntry{
		response:  resp.Copy(),
		expiresAt: time.Now().Add(time.Duration(ttl) * time.Second),
	}
}

// Clean expired entries
func (c *dnsCache) CleanExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for key, entry := range c.entries {
		if now.After(entry.expiresAt) {
			delete(c.entries, key)
		}
	}
}

var cache = newDNSCache()

// 查询上游 DNS
func queryDNS(r *dns.Msg, server string) (*dns.Msg, error) {
	c := &dns.Client{
		Net:     "udp",
		Timeout: 3 * time.Second,
	}
	resp, _, err := c.Exchange(r, server)
	return resp, err
}

// 随机顺序遍历上游，实现简单负载均衡与容错
func queryWithLoadBalance(r *dns.Msg, servers []string) (*dns.Msg, string, error) {
	if len(servers) == 0 {
		return nil, "", nil
	}

	rngMu.Lock()
	order := rng.Perm(len(servers))
	rngMu.Unlock()

	var lastErr error
	for _, idx := range order {
		target := servers[idx]
		resp, err := queryDNS(r, target)
		if err == nil && resp != nil {
			return resp, target, nil
		}
		lastErr = err
	}
	return nil, "", lastErr
}

// Get minimum TTL from DNS response
func getMinTTL(resp *dns.Msg) uint32 {
	if resp == nil || len(resp.Answer) == 0 {
		return 300 // Default 5 minutes
	}

	minTTL := uint32(3600) // Max 1 hour
	for _, ans := range resp.Answer {
		if ans.Header().Ttl < minTTL {
			minTTL = ans.Header().Ttl
		}
	}

	// Ensure minimum TTL of 60 seconds
	if minTTL < 60 {
		minTTL = 60
	}
	return minTTL
}

// Generate cache key from DNS question
func getCacheKey(r *dns.Msg) string {
	if len(r.Question) == 0 {
		return ""
	}
	q := r.Question[0]
	return q.Name + ":" + dns.TypeToString[q.Qtype]
}

func handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	cacheKey := getCacheKey(r)
	if cacheKey != "" {
		if cachedResp, found := cache.Get(cacheKey); found {
			log.Printf("Cache hit for %s", cacheKey)
			cachedResp.Id = r.Id
			w.WriteMsg(cachedResp)
			return
		}
	}

	resp, upstream, err := queryWithLoadBalance(r, googleIPv6Servers)
	if err != nil || resp == nil {
		log.Printf("IPv6 upstream failed: %v", err)
		dns.HandleFailed(w, r)
		return
	}

	log.Printf("Answered via IPv6 upstream %s", upstream)

	finalResp := resp
	needsIPv4Replace := false
	for _, ans := range resp.Answer {
		if _, ok := ans.(*dns.A); ok {
			needsIPv4Replace = true
			break
		}
	}

	if needsIPv4Replace {
		ipv4Query := r.Copy()
		if len(ipv4Query.Question) > 0 {
			ipv4Query.Question[0].Qtype = dns.TypeA
		}

		ipv4Resp, v4Upstream, v4Err := queryWithLoadBalance(ipv4Query, cloudflareIPv4Servers)
		if v4Err == nil && ipv4Resp != nil {
			replaced := resp.Copy()
			replaced.Answer = replaced.Answer[:0]
			for _, ans := range resp.Answer {
				if _, ok := ans.(*dns.A); ok {
					continue
				}
				replaced.Answer = append(replaced.Answer, ans)
			}
			for _, ans := range ipv4Resp.Answer {
				if a, ok := ans.(*dns.A); ok {
					replaced.Answer = append(replaced.Answer, a)
				}
			}
			finalResp = replaced
			log.Printf("Replaced A records via IPv4 upstream %s", v4Upstream)
		} else {
			log.Printf("IPv4 upstream failed, keep original IPv4 records: %v", v4Err)
		}
	}

	if cacheKey != "" {
		cache.Set(cacheKey, finalResp, getMinTTL(finalResp))
	}

	finalResp.Id = r.Id
	w.WriteMsg(finalResp)
}

func main() {
	// Start cache cleanup goroutine
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			cache.CleanExpired()
			log.Println("Cache cleanup completed")
		}
	}()

	dns.HandleFunc(".", handleDNS)

	// UDP
	go func() {
		server := &dns.Server{
			Addr: ":5353",
			Net:  "udp",
		}
		log.Println("DNS server started on UDP :5353")
		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("UDP server failed: %v", err)
		}
	}()

	// TCP
	server := &dns.Server{
		Addr: ":5353",
		Net:  "tcp",
	}
	log.Println("DNS server started on TCP :5353")
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("TCP server failed: %v", err)
	}
}
