// orbit.go — ZERO-ORBIT networking / HTTP engine.
//
// Modes:
//   discover  → subdomains (DNS) + common ports (TCP connect)
//   scan      → HTTP headers, endpoints on common paths, safe probes
//   pressure  → controlled, strictly rate-limited traffic test
//
// Outputs JSON to stdout. Never sends more than the configured limits.

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---------- Data types ----------

type DiscoverOutput struct {
	Target       string                 `json:"target"`
	Assets       map[string]interface{} `json:"assets"`
	Technologies []string               `json:"technologies"`
}

type EndpointResult struct {
	URL    string `json:"url"`
	Status int    `json:"status"`
	Length int    `json:"length"`
	Ms     int64  `json:"ms"`
}

type ScanOutput struct {
	Target          string            `json:"target"`
	Headers         map[string]string `json:"headers"`
	Endpoints       []string          `json:"endpoints"`
	EndpointResults []EndpointResult  `json:"endpoint_results"`
	BodySnippet     string            `json:"body_snippet"`
	Status          int               `json:"status"`
	TimeMs          int64             `json:"time_ms"`
}

type PressureOutput struct {
	Target      string  `json:"target"`
	Duration    int     `json:"duration_seconds"`
	Requests    int64   `json:"requests_sent"`
	RPS         float64 `json:"requests_per_sec"`
	Concurrency int     `json:"concurrency"`
	Errors      int64   `json:"errors"`
	Rate429     int64   `json:"rate_limited_429"`
	Server5xx   int64   `json:"server_5xx"`
	MinMs       int64   `json:"min_ms"`
	MaxMs       int64   `json:"max_ms"`
	AvgMs       float64 `json:"avg_ms"`
	Aborted     bool    `json:"aborted_by_limit"`
}

// ---------- Helpers ----------

func normalizeTarget(t string) string {
	if t == "" {
		return ""
	}
	if !strings.HasPrefix(t, "http://") && !strings.HasPrefix(t, "https://") {
		return "https://" + t
	}
	return t
}

func hostOnly(t string) string {
	s := t
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/:"); i >= 0 {
		s = s[:i]
	}
	return s
}

func httpClient(timeout time.Duration) *http.Client {
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        64,
		MaxIdleConnsPerHost: 16,
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}
	return &http.Client{Timeout: timeout, Transport: tr, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return http.ErrUseLastResponse
		}
		return nil
	}}
}

func emit(v interface{}) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// ---------- Discovery ----------

var commonSubs = []string{"www", "api", "dev", "staging", "test", "admin", "portal", "mail", "cdn", "app"}

var commonPorts = []int{80, 443, 8080, 8443, 8000, 3000, 5000, 22, 21, 25, 3306, 5432, 6379}

func runDiscover(target string, timeout time.Duration) DiscoverOutput {
	base := hostOnly(target)
	out := DiscoverOutput{Target: base, Assets: map[string]interface{}{}, Technologies: []string{}}

	// DNS resolution
	ips, _ := net.LookupHost(base)
	out.Assets["ip_addresses"] = ips

	// Subdomains via DNS
	var subWg sync.WaitGroup
	var subMu sync.Mutex
	foundSubs := []string{}
	for _, s := range commonSubs {
		subWg.Add(1)
		go func(sub string) {
			defer subWg.Done()
			fqdn := sub + "." + base
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			addrs, err := net.DefaultResolver.LookupHost(ctx, fqdn)
			if err == nil && len(addrs) > 0 {
				subMu.Lock()
				foundSubs = append(foundSubs, fqdn)
				subMu.Unlock()
			}
		}(s)
	}
	subWg.Wait()
	out.Assets["subdomains"] = foundSubs

	// TCP connect port scan (limited and safe)
	openPorts := []int{}
	var portWg sync.WaitGroup
	var portMu sync.Mutex
	for _, p := range commonPorts {
		portWg.Add(1)
		go func(port int) {
			defer portWg.Done()
			addr := net.JoinHostPort(base, strconv.Itoa(port))
			conn, err := net.DialTimeout("tcp", addr, timeout)
			if err == nil {
				_ = conn.Close()
				portMu.Lock()
				openPorts = append(openPorts, port)
				portMu.Unlock()
			}
		}(p)
	}
	portWg.Wait()
	out.Assets["open_ports"] = openPorts

	// Basic technology hints from primary response
	client := httpClient(timeout)
	resp, err := client.Get(normalizeTarget(target))
	if err == nil {
		defer resp.Body.Close()
		if srv := resp.Header.Get("Server"); srv != "" {
			out.Technologies = append(out.Technologies, "Server:"+srv)
		}
		if xp := resp.Header.Get("X-Powered-By"); xp != "" {
			out.Technologies = append(out.Technologies, "X-Powered-By:"+xp)
		}
	}
	return out
}

// ---------- Web scan ----------

var commonEndpoints = []string{
	"/", "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
	"/admin", "/administrator", "/dashboard", "/manage", "/control",
	"/login", "/signin", "/api", "/api/v1", "/health", "/status",
	"/actuator", "/actuator/health", "/swagger", "/swagger-ui",
	"/openapi.json", "/graphql", "/.git/HEAD", "/.env",
}

func runScan(target string, timeout time.Duration, maxReq int) ScanOutput {
	baseURL := normalizeTarget(target)
	client := httpClient(timeout)
	out := ScanOutput{Target: baseURL, Headers: map[string]string{}, Endpoints: []string{}}

	// Primary request
	start := time.Now()
	resp, err := client.Get(baseURL)
	if err != nil {
		emit(map[string]string{"error": err.Error(), "target": baseURL})
		return out
	}
	defer resp.Body.Close()
	out.Status = resp.StatusCode
	out.TimeMs = time.Since(start).Milliseconds()

	for k, v := range resp.Header {
		out.Headers[k] = strings.Join(v, ", ")
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	out.BodySnippet = string(body)

	// Endpoint discovery — bounded
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	var mu sync.Mutex
	results := []EndpointResult{}
	var counter int64

	for _, ep := range commonEndpoints {
		if int(atomic.LoadInt64(&counter)) >= maxReq {
			break
		}
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			atomic.AddInt64(&counter, 1)

			url := strings.TrimRight(baseURL, "/") + path
			req, _ := http.NewRequest("GET", url, nil)
			req.Header.Set("User-Agent", "ZERO-ORBIT/1.0 (authorized)")
			t0 := time.Now()
			r, err := client.Do(req)
			if err != nil {
				return
			}
			defer r.Body.Close()
			n, _ := io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))
			mu.Lock()
			results = append(results, EndpointResult{
				URL: url, Status: r.StatusCode,
				Length: int(n), Ms: time.Since(t0).Milliseconds(),
			})
			out.Endpoints = append(out.Endpoints, url)
			mu.Unlock()
		}(ep)
	}
	wg.Wait()
	out.EndpointResults = results
	return out
}

// ---------- Pressure Lab ----------

func runPressure(target string, rps, duration, concurrency, maxReq int, timeout time.Duration) PressureOutput {
	baseURL := normalizeTarget(target)
	client := httpClient(timeout)
	out := PressureOutput{Target: baseURL, Duration: duration, Concurrency: concurrency}

	if rps <= 0 {
		rps = 1
	}
	if duration <= 0 {
		duration = 10
	}
	if concurrency <= 0 {
		concurrency = 1
	}
	if maxReq <= 0 {
		maxReq = rps * duration
	}

	var sent, errs, r429, r5xx int64
	var minMs, maxMs int64 = 1 << 62, 0
	var totalMs int64

	// Token bucket
	tick := time.Duration(float64(time.Second) / float64(rps))
	ticker := time.NewTicker(tick)
	defer ticker.Stop()

	deadline := time.Now().Add(time.Duration(duration) * time.Second)
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex

loop:
	for time.Now().Before(deadline) {
		if atomic.LoadInt64(&sent) >= int64(maxReq) {
			out.Aborted = true
			break loop
		}
		select {
		case <-ticker.C:
		case <-time.After(200 * time.Millisecond):
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			atomic.AddInt64(&sent, 1)

			req, _ := http.NewRequest("GET", baseURL, nil)
			req.Header.Set("User-Agent", "ZERO-ORBIT/1.0 (authorized-pressure)")
			t0 := time.Now()
			r, err := client.Do(req)
			ms := time.Since(t0).Milliseconds()
			if err != nil {
				atomic.AddInt64(&errs, 1)
				return
			}
			defer r.Body.Close()
			_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 1<<16))

			mu.Lock()
			totalMs += ms
			if ms < minMs {
				minMs = ms
			}
			if ms > maxMs {
				maxMs = ms
			}
			mu.Unlock()

			if r.StatusCode == 429 {
				atomic.AddInt64(&r429, 1)
			}
			if r.StatusCode >= 500 {
				atomic.AddInt64(&r5xx, 1)
			}
		}()
	}
	wg.Wait()

	out.Requests = sent
	out.Errors = errs
	out.Rate429 = r429
	out.Server5xx = r5xx
	if sent > 0 {
		out.RPS = float64(sent) / float64(duration)
		out.AvgMs = float64(totalMs) / float64(sent)
	}
	if minMs == 1<<62 {
		minMs = 0
	}
	out.MinMs = minMs
	out.MaxMs = maxMs
	return out
}

// ---------- Main ----------

func main() {
	mode := flag.String("mode", "scan", "discover|scan|pressure")
	target := flag.String("target", "", "authorized target")
	timeout := flag.Int("timeout", 10, "per-request timeout (seconds)")
	maxReq := flag.Int("max-requests", 200, "max total requests")
	rps := flag.Int("rps", 5, "requests per second (pressure)")
	duration := flag.Int("duration", 30, "duration seconds (pressure)")
	concurrency := flag.Int("concurrency", 4, "concurrent workers (pressure)")
	flag.Parse()

	if *target == "" {
		fmt.Fprintln(os.Stderr, "orbit: --target is required")
		os.Exit(2)
	}

	t := time.Duration(*timeout) * time.Second

	switch *mode {
	case "discover":
		emit(runDiscover(*target, t))
	case "scan":
		emit(runScan(*target, t, *maxReq))
	case "pressure":
		emit(runPressure(*target, *rps, *duration, *concurrency, *maxReq, t))
	default:
		fmt.Fprintln(os.Stderr, "orbit: unknown mode")
		os.Exit(2)
	}
}