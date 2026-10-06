package bluecat

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// defaultRequestTimeout bounds a single HTTP attempt. The client-level
	// timeout is a much longer backstop for pathological cases.
	defaultRequestTimeout = 30 * time.Second

	// defaultClientTimeout is the whole-request backstop, generous enough for
	// very large zone enumerations.
	defaultClientTimeout = 180 * time.Second

	// maxResponseBody caps how much of a response we will read into memory.
	maxResponseBody = 8 << 20

	// authFailCooldown is how long to wait before retrying authentication
	// after it failed with a credential error. Without this, three load
	// balancer nodes retrying in a loop can lock out the service account.
	authFailCooldown = 30 * time.Second
)

// Client handles communication with the Bluecat Address Manager v2 API.
//
// A Client is safe for concurrent use. It authenticates lazily on first use
// and re-authenticates automatically when Bluecat rejects a session.
type Client struct {
	baseURL  string
	username string
	password string

	httpClient     *http.Client
	requestTimeout time.Duration

	// credMu guards the session credentials and their generation counter.
	credMu     sync.RWMutex
	authHeader string
	authGen    uint64

	// authMu serialises authentication attempts so that N goroutines seeing
	// a 401 at the same time produce exactly one re-authentication.
	authMu       sync.Mutex
	lastAuthFail time.Time
	authFailErr  error

	// sleep is the backoff sleep, overridable in tests.
	sleep func(ctx context.Context, d time.Duration) error

	// rand guards jitter generation.
	randMu sync.Mutex
	rand   *rand.Rand

	// pageLimit is the page size used by listAll.
	pageLimit int

	// zones caches resolved zone IDs.
	zones zoneCache

	// deployPollInterval is how often to poll for deployment completion.
	deployPollInterval time.Duration
	// deployPollTimeout is how long to wait for a deployment to complete.
	deployPollTimeout time.Duration
}

// NewClient creates a new Bluecat API client. It does not contact the server;
// authentication happens on the first request.
func NewClient(baseURL, username, password string) (*Client, error) {
	baseURL = strings.TrimSuffix(baseURL, "/")
	if baseURL == "" {
		return nil, fmt.Errorf("bluecat: server URL is required")
	}
	if _, err := url.Parse(baseURL); err != nil {
		return nil, fmt.Errorf("bluecat: invalid server URL %q: %w", baseURL, err)
	}

	return &Client{
		baseURL:        baseURL,
		username:       username,
		password:       password,
		httpClient:     &http.Client{Timeout: defaultClientTimeout},
		requestTimeout: defaultRequestTimeout,
		sleep:          sleepCtx,
		rand:           rand.New(rand.NewSource(time.Now().UnixNano())),

		pageLimit:          100,
		deployPollInterval: 3 * time.Second,
		deployPollTimeout:  120 * time.Second,
	}, nil
}

// retryPolicy controls how a request is retried on transient failure.
type retryPolicy struct {
	// MaxAttempts is the total number of attempts, including the first.
	MaxAttempts int
	// Base is the first backoff interval; it doubles each attempt.
	Base time.Duration
	// Max caps a single backoff interval.
	Max time.Duration
	// Unsafe marks a non-idempotent request. Unsafe requests are not retried
	// on transport errors or 5xx responses: a retried POST to
	// /resourceRecords is precisely how a duplicate — and the 409 that
	// follows it — gets manufactured.
	Unsafe bool
}

func defaultRetry() retryPolicy {
	return retryPolicy{MaxAttempts: 4, Base: 500 * time.Millisecond, Max: 5 * time.Second}
}

// unsafeRetry is for requests that must not be replayed. Auth failures are
// still handled, but transport errors and 5xx responses surface to the caller.
func unsafeRetry() retryPolicy {
	return retryPolicy{MaxAttempts: 1, Unsafe: true}
}

// apiRequest describes a single Bluecat API call.
type apiRequest struct {
	Method string
	// Path is the server-relative path, e.g. "/api/v2/zones/42/resourceRecords".
	Path string
	// Query holds URL query parameters, if any.
	Query url.Values
	// Body is marshalled to JSON once, before the retry loop.
	Body any
	// Out receives the decoded response body. Nil discards it.
	Out any
	// OK lists accepted status codes. Empty means "any 2xx".
	OK []int
	// Status, when non-nil, receives the response status code on success.
	Status *int
	// Retry controls retry behaviour; the zero value means defaultRetry.
	Retry *retryPolicy
}

// do executes r, handling authentication, re-authentication on session
// expiry, retries with backoff, and error decoding.
func (c *Client) do(ctx context.Context, r apiRequest) error {
	// Marshal once so every attempt sends identical bytes.
	var body []byte
	if r.Body != nil {
		var err error
		body, err = json.Marshal(r.Body)
		if err != nil {
			return fmt.Errorf("bluecat: marshal %s %s: %w", r.Method, r.Path, err)
		}
	}

	policy := defaultRetry()
	if r.Retry != nil {
		policy = *r.Retry
	}
	if policy.MaxAttempts < 1 {
		policy.MaxAttempts = 1
	}

	endpoint := c.baseURL + r.Path
	if len(r.Query) > 0 {
		endpoint += "?" + r.Query.Encode()
	}

	// reauthed limits us to one re-authentication per call, so an endpoint
	// that always returns 401 can't drive an auth loop.
	var reauthed bool
	var lastErr error

	for attempt := 1; attempt <= policy.MaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}

		header, gen, err := c.credentials(ctx)
		if err != nil {
			return err
		}

		res, err := c.attempt(ctx, r.Method, endpoint, body, header)
		if err == nil {
			if isAcceptable(res.status, r.OK) {
				if r.Status != nil {
					*r.Status = res.status
				}
				return decodeInto(res.body, r.Out, r.Method, r.Path)
			}
			err = parseAPIError(r.Method, r.Path, res.status, res.body)
		}
		lastErr = err

		// An expired session looks like any other 401. Refresh once and
		// retry immediately — this doesn't consume a transient attempt.
		if IsAuthError(err) && !reauthed {
			reauthed = true
			if refreshErr := c.refreshAuth(ctx, gen); refreshErr != nil {
				return fmt.Errorf("bluecat: re-authenticate after %w: %w", err, refreshErr)
			}
			attempt--
			continue
		}

		if attempt == policy.MaxAttempts || policy.Unsafe || !IsRetryable(err) {
			return lastErr
		}

		if waitErr := c.sleep(ctx, c.backoff(policy, attempt, res)); waitErr != nil {
			return waitErr
		}
	}

	return lastErr
}

// response is one completed HTTP round trip, fully read.
type response struct {
	status  int
	body    []byte
	headers http.Header
}

// attempt performs one HTTP round trip and reads the response body.
func (c *Client) attempt(ctx context.Context, method, endpoint string, body []byte, authHeader string) (response, error) {
	attemptCtx, cancel := context.WithTimeout(ctx, c.requestTimeout)
	defer cancel()

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(attemptCtx, method, endpoint, reader)
	if err != nil {
		return response{}, fmt.Errorf("bluecat: build %s %s: %w", method, endpoint, err)
	}

	if body != nil {
		req.ContentLength = int64(len(body))
		// GetBody lets the transport replay the body across redirects and
		// connection retries without us holding a consumed reader.
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(body)), nil
		}
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if authHeader != "" {
		req.Header.Set("Authorization", "Basic "+authHeader)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return response{}, fmt.Errorf("bluecat: %s %s: %w", method, endpoint, err)
	}

	// Read and close before returning so the connection goes back to the pool
	// before any backoff sleep, and so the same bytes can feed both the
	// success decode and the error envelope.
	respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	resp.Body.Close()
	if readErr != nil {
		return response{status: resp.StatusCode, headers: resp.Header},
			fmt.Errorf("bluecat: read %s %s: %w", method, endpoint, readErr)
	}

	return response{status: resp.StatusCode, body: respBody, headers: resp.Header}, nil
}

func isAcceptable(status int, ok []int) bool {
	if len(ok) == 0 {
		return status >= 200 && status < 300
	}
	for _, code := range ok {
		if status == code {
			return true
		}
	}
	return false
}

func decodeInto(body []byte, out any, method, path string) error {
	if out == nil || len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("bluecat: decode %s %s response: %w", method, path, err)
	}
	return nil
}

// backoff returns how long to wait before the next attempt, honouring a
// Retry-After header when the server sent one.
func (c *Client) backoff(policy retryPolicy, attempt int, res response) time.Duration {
	if res.status == http.StatusTooManyRequests || res.status == http.StatusServiceUnavailable {
		if d, ok := retryAfter(res.headers); ok {
			return d
		}
	}

	base := policy.Base
	if base <= 0 {
		base = 500 * time.Millisecond
	}
	max := policy.Max
	if max <= 0 {
		max = 5 * time.Second
	}

	d := base << (attempt - 1)
	if d > max || d <= 0 {
		d = max
	}

	// Full jitter: spread retries from concurrent challenges so they don't
	// re-collide in lockstep.
	c.randMu.Lock()
	jittered := time.Duration(c.rand.Int63n(int64(d) + 1))
	c.randMu.Unlock()

	return jittered
}

// retryAfter parses a Retry-After header, which may be either a number of
// seconds or an HTTP date.
func retryAfter(h http.Header) (time.Duration, bool) {
	v := h.Get("Retry-After")
	if v == "" {
		return 0, false
	}

	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			return 0, false
		}
		return time.Duration(secs) * time.Second, true
	}

	if when, err := http.ParseTime(v); err == nil {
		if d := time.Until(when); d > 0 {
			return d, true
		}
		return 0, true
	}

	return 0, false
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// credentials returns the current session header and its generation,
// authenticating first if we have never done so.
func (c *Client) credentials(ctx context.Context) (string, uint64, error) {
	c.credMu.RLock()
	header, gen := c.authHeader, c.authGen
	c.credMu.RUnlock()

	if gen != 0 {
		return header, gen, nil
	}

	if err := c.refreshAuth(ctx, 0); err != nil {
		return "", 0, err
	}

	c.credMu.RLock()
	defer c.credMu.RUnlock()
	return c.authHeader, c.authGen, nil
}

// refreshAuth authenticates, unless another goroutine already replaced the
// generation staleGen was read from. Concurrent callers that all observed the
// same stale generation produce exactly one authentication request.
func (c *Client) refreshAuth(ctx context.Context, staleGen uint64) error {
	c.authMu.Lock()
	defer c.authMu.Unlock()

	// Someone else refreshed while we waited for the lock.
	c.credMu.RLock()
	current := c.authGen
	c.credMu.RUnlock()
	if current != staleGen {
		return nil
	}

	// Don't hammer Bluecat with bad credentials; that's how accounts get
	// locked out when three nodes retry in a loop.
	if !c.lastAuthFail.IsZero() && time.Since(c.lastAuthFail) < authFailCooldown {
		return fmt.Errorf("bluecat: authentication is in cooldown after a credential failure: %w", c.authFailErr)
	}

	header, err := c.authenticate(ctx)
	if err != nil {
		if IsAuthError(err) {
			c.lastAuthFail = time.Now()
			c.authFailErr = err
		}
		return err
	}

	c.lastAuthFail = time.Time{}
	c.authFailErr = nil

	c.credMu.Lock()
	c.authHeader = header
	c.authGen++
	c.credMu.Unlock()

	return nil
}

// authenticate performs the session request and returns the credentials
// Bluecat issued. It does not touch Client state.
func (c *Client) authenticate(ctx context.Context) (string, error) {
	if c.username == "" || c.password == "" {
		return "", fmt.Errorf("bluecat: username and password are required")
	}

	payload, err := json.Marshal(map[string]string{
		"username": c.username,
		"password": c.password,
	})
	if err != nil {
		return "", fmt.Errorf("bluecat: marshal auth request: %w", err)
	}

	// Authenticating cannot itself go through do(): that would recurse.
	res, err := c.attempt(ctx, http.MethodPost, c.baseURL+"/api/v2/sessions", payload, "")
	if err != nil {
		return "", err
	}
	if !isAcceptable(res.status, []int{http.StatusCreated, http.StatusOK}) {
		return "", parseAPIError(http.MethodPost, "/api/v2/sessions", res.status, res.body)
	}

	var authResp struct {
		APIToken                       string `json:"apiToken"`
		BasicAuthenticationCredentials string `json:"basicAuthenticationCredentials"`
	}
	if err := json.Unmarshal(res.body, &authResp); err != nil {
		return "", fmt.Errorf("bluecat: decode auth response: %w", err)
	}

	// Without this check an empty header yields "Authorization: Basic " on
	// every subsequent call — permanent 401s that look like a missing zone.
	if authResp.BasicAuthenticationCredentials == "" {
		return "", fmt.Errorf("bluecat: authentication succeeded but returned no basicAuthenticationCredentials")
	}

	return authResp.BasicAuthenticationCredentials, nil
}

// setCredentials seeds session credentials directly. Used by tests to skip
// the authentication round trip.
func (c *Client) setCredentials(header string) {
	c.credMu.Lock()
	defer c.credMu.Unlock()
	c.authHeader = header
	c.authGen++
}

// collection is the Bluecat v2 envelope for a list endpoint. Its "count" is
// the number of items in this page, not the collection total, and there is no
// total or next link, so a short page is the only end-of-collection signal.
type collection[T any] struct {
	Data []T `json:"data"`
}

// maxPages guards against a server that ignores offset and returns the same
// full page forever.
const maxPages = 200

// listAll fetches every page of a collection endpoint, following limit/offset
// until the collection is exhausted.
func listAll[T any](ctx context.Context, c *Client, path string, query url.Values) ([]T, error) {
	if query == nil {
		query = url.Values{}
	}

	limit := c.pageLimit
	if limit <= 0 {
		limit = 100
	}

	var all []T
	for page := 0; page < maxPages; page++ {
		q := cloneValues(query)
		q.Set("limit", strconv.Itoa(limit))
		q.Set("offset", strconv.Itoa(len(all)))

		var resp collection[T]
		if err := c.do(ctx, apiRequest{
			Method: http.MethodGet,
			Path:   path,
			Query:  q,
			Out:    &resp,
		}); err != nil {
			return nil, err
		}

		all = append(all, resp.Data...)

		// A short page means we reached the end. An empty page means the
		// same, and also protects against a server that ignores offset.
		if len(resp.Data) < limit {
			return all, nil
		}
	}

	return all, fmt.Errorf("bluecat: %s: pagination exceeded %d pages (%d items); server may be ignoring offset", path, maxPages, len(all))
}

func cloneValues(v url.Values) url.Values {
	out := make(url.Values, len(v)+2)
	for k, vals := range v {
		out[k] = append([]string(nil), vals...)
	}
	return out
}
