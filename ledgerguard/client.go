// Package ledgerguard is ARTEX's money-invariant assurance engine for banking
// and payments stacks. Where a web scanner asks "is there an injection?",
// LedgerGuard asks the question a bank's board actually cares about: "can an
// API caller make money appear, disappear, or move without authority?"
//
// It drives a target's public API with short, budgeted attack sequences
// (concurrency, replay, sign/rounding abuse, authorization swaps) and judges
// every sequence against a read-only reconciliation oracle. A finding is only
// raised when a ledger invariant is observably broken, and it carries the
// exact HTTP exchanges, the rupee exposure, and the regulatory controls hit.
package ledgerguard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Exchange is one captured request/response pair kept as evidence.
type Exchange struct {
	Method     string `json:"method"`
	URL        string `json:"url"`
	Identity   string `json:"identity"`
	ReqBody    string `json:"request_body,omitempty"`
	Status     int    `json:"status"`
	RespBody   string `json:"response_body"`
	DurationMS int64  `json:"duration_ms"`
}

// ErrBudget is returned once the request budget is spent.
var ErrBudget = errors.New("ledgerguard: request budget exhausted")

// Client is a scope-confined, budgeted HTTP client. Every request it sends is
// recorded so findings can cite the traffic that proves them.
type Client struct {
	base    *url.URL
	tokens  map[string]string // identity -> bearer token
	http    *http.Client
	budget  int64
	used    atomic.Int64
	mu      sync.Mutex
	journal []Exchange
}

// NewClient refuses any base URL whose host is not in allowHosts. This is the
// engine's first brake: nothing leaves the declared scope.
func NewClient(base string, tokens map[string]string, allowHosts []string, budget int) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("ledgerguard: unsupported scheme %q", u.Scheme)
	}
	ok := false
	for _, h := range allowHosts {
		if strings.EqualFold(strings.TrimSpace(h), u.Hostname()) {
			ok = true
		}
	}
	if !ok {
		return nil, fmt.Errorf("ledgerguard: host %q is not in the authorized scope %v", u.Hostname(), allowHosts)
	}
	if budget <= 0 {
		budget = 500
	}
	return &Client{
		base:   u,
		tokens: tokens,
		budget: int64(budget),
		http: &http.Client{
			Timeout: 10 * time.Second,
			// Never follow redirects out of scope.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// Do sends one request as identity and decodes a JSON response into out (may be nil).
func (c *Client) Do(ctx context.Context, identity, method, path string, body any, out any) (Exchange, error) {
	if c.used.Add(1) > c.budget {
		return Exchange{}, ErrBudget
	}
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			return Exchange{}, err
		}
	}
	target := c.base.ResolveReference(&url.URL{Path: path})
	req, err := http.NewRequestWithContext(ctx, method, target.String(), bytes.NewReader(raw))
	if err != nil {
		return Exchange{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ARTEX-LedgerGuard/0.1 (authorized assurance)")
	if tok := c.tokens[identity]; tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	start := time.Now()
	resp, err := c.http.Do(req)
	if err != nil {
		return Exchange{}, err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	ex := Exchange{
		Method: method, URL: target.String(), Identity: identity, ReqBody: string(raw),
		Status: resp.StatusCode, RespBody: strings.TrimSpace(string(rb)),
		DurationMS: time.Since(start).Milliseconds(),
	}
	c.mu.Lock()
	c.journal = append(c.journal, ex)
	c.mu.Unlock()
	if out != nil && len(rb) > 0 {
		_ = json.Unmarshal(rb, out)
	}
	return ex, nil
}

// Used reports how many requests have been spent.
func (c *Client) Used() int64 { return c.used.Load() }
