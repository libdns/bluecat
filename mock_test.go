package bluecat

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// recordedCall is one request the mock server received.
type recordedCall struct {
	Method string
	Path   string
	Query  map[string][]string
	Body   string
}

// Filter returns the unescaped "filter" query parameter.
func (c recordedCall) Filter() string {
	if v, ok := c.Query["filter"]; ok && len(v) > 0 {
		return v[0]
	}
	return ""
}

type handlerFn func(w http.ResponseWriter, r *http.Request)

// mockBAM is a scriptable stand-in for Bluecat Address Manager.
//
// Handlers are registered per method+path and consumed in order, so a test can
// script a sequence like "first POST conflicts, the following GET returns the
// conflicting record".
type mockBAM struct {
	t      *testing.T
	server *httptest.Server

	mu     sync.Mutex
	calls  []recordedCall
	routes map[string][]handlerFn
	slept  []time.Duration
}

func newMockBAM(t *testing.T) *mockBAM {
	t.Helper()

	m := &mockBAM{t: t, routes: make(map[string][]handlerFn)}
	m.server = httptest.NewServer(http.HandlerFunc(m.serve))
	t.Cleanup(m.server.Close)

	// Every client authenticates lazily; unless a test scripts its own
	// session responses, hand out a token on demand.
	m.OnAny(http.MethodPost, "/api/v2/sessions", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusCreated, map[string]string{
			"apiToken":                       "tok",
			"basicAuthenticationCredentials": "creds",
		})
	})

	return m
}

func routeKey(method, path string) string { return method + " " + path }

// On registers handlers consumed in order, one per matching request.
func (m *mockBAM) On(method, path string, hs ...handlerFn) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := routeKey(method, path)
	m.routes[key] = append(m.routes[key], hs...)
}

// OnAny registers a handler that serves every matching request. It is only
// used when no sequenced handler remains for that route.
func (m *mockBAM) OnAny(method, path string, h handlerFn) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.routes["*"+routeKey(method, path)] = []handlerFn{h}
}

func (m *mockBAM) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	r.Body.Close()

	m.mu.Lock()
	m.calls = append(m.calls, recordedCall{
		Method: r.Method,
		Path:   r.URL.Path,
		Query:  r.URL.Query(),
		Body:   string(body),
	})

	key := routeKey(r.Method, r.URL.Path)
	var h handlerFn
	if queue := m.routes[key]; len(queue) > 0 {
		h = queue[0]
		m.routes[key] = queue[1:]
	} else if fallback := m.routes["*"+key]; len(fallback) > 0 {
		h = fallback[0]
	}
	m.mu.Unlock()

	if h == nil {
		m.t.Errorf("mockBAM: unexpected request %s %s", r.Method, r.URL.RequestURI())
		writeJSON(w, http.StatusNotImplemented, map[string]any{
			"status": http.StatusNotImplemented,
			"code":   "NoHandler",
		})
		return
	}

	// Restore the body so handlers can read it.
	r.Body = io.NopCloser(strings.NewReader(string(body)))
	h(w, r)
}

// Calls returns every recorded request matching method and path. An empty
// method or path matches anything.
func (m *mockBAM) Calls(method, path string) []recordedCall {
	m.mu.Lock()
	defer m.mu.Unlock()

	var out []recordedCall
	for _, c := range m.calls {
		if method != "" && c.Method != method {
			continue
		}
		if path != "" && c.Path != path {
			continue
		}
		out = append(out, c)
	}
	return out
}

func (m *mockBAM) CountCalls(method, path string) int { return len(m.Calls(method, path)) }

// Client returns a client pointing at the mock, with backoff made instant so
// retry tests don't actually sleep.
func (m *mockBAM) Client(t *testing.T) *Client {
	t.Helper()

	c, err := NewClient(m.server.URL, "user", "pass")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	c.sleep = func(_ context.Context, d time.Duration) error {
		m.mu.Lock()
		m.slept = append(m.slept, d)
		m.mu.Unlock()
		return nil
	}
	return c
}

// Provider returns a provider wired to the mock with deploys disabled by
// default, so record tests don't have to script deployment traffic.
func (m *mockBAM) Provider(t *testing.T) *Provider {
	t.Helper()

	p := &Provider{
		ServerURL:     m.server.URL,
		Username:      "user",
		Password:      "pass",
		ViewName:      "external",
		DisableDeploy: true,
	}
	p.client = m.Client(t)
	return p
}

// Slept returns the backoff durations the client asked for.
func (m *mockBAM) Slept() []time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]time.Duration(nil), m.slept...)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// apiErrorBody builds a Bluecat error envelope.
func apiErrorBody(status int, reason, code, message, detail string) map[string]any {
	return map[string]any{
		"status":  status,
		"reason":  reason,
		"code":    code,
		"message": message,
		"detail":  detail,
	}
}

// conflict is the exact envelope Bluecat returns for a duplicate record.
func conflict() map[string]any {
	return apiErrorBody(http.StatusConflict, "Conflict", codeResourceAlreadyExists,
		"The request attempted to create a resource that already exists",
		"Duplicate of another item")
}

// zoneResponse serves a single-zone lookup result.
func zoneResponse(id int64, absoluteName string) handlerFn {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"data": []map[string]any{
				{"id": id, "name": strings.SplitN(absoluteName, ".", 2)[0], "absoluteName": absoluteName},
			},
			"count": 1,
		})
	}
}

// recordsResponse serves a resourceRecords collection.
func recordsResponse(records ...map[string]any) handlerFn {
	return func(w http.ResponseWriter, r *http.Request) {
		if records == nil {
			records = []map[string]any{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": records, "count": len(records)})
	}
}

// txtRecord builds a Bluecat TXT record payload.
func txtRecord(id int64, name, text, zone string) map[string]any {
	abs := name + "." + zone
	if name == "" || name == "@" {
		abs = zone
	}
	return map[string]any{
		"id":           id,
		"type":         "TXTRecord",
		"recordType":   "TXT",
		"name":         name,
		"absoluteName": abs,
		"text":         text,
		"ttl":          300,
	}
}

func mustContain(t *testing.T, got, want, what string) {
	t.Helper()
	if !strings.Contains(got, want) {
		t.Errorf("expected %s to contain %q, got %q", what, want, got)
	}
}

func itoa(i int) string { return strconv.Itoa(i) }

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

// decodeBody decodes a request body into v.
func decodeBody(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
