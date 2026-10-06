package bluecat

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// zoneCacheTTL is how long a resolved zone ID is reused. Zones are created and
// deleted rarely; record churn is what's frequent.
const zoneCacheTTL = 5 * time.Minute

type zoneCacheEntry struct {
	id        int64
	expiresAt time.Time
}

type zoneCache struct {
	mu sync.RWMutex
	m  map[string]zoneCacheEntry
}

func (z *zoneCache) get(key string) (int64, bool) {
	z.mu.RLock()
	defer z.mu.RUnlock()
	e, ok := z.m[key]
	if !ok || time.Now().After(e.expiresAt) {
		return 0, false
	}
	return e.id, true
}

func (z *zoneCache) put(key string, id int64) {
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.m == nil {
		z.m = make(map[string]zoneCacheEntry)
	}
	z.m[key] = zoneCacheEntry{id: id, expiresAt: time.Now().Add(zoneCacheTTL)}
}

// bluecatZone is the subset of the Bluecat zone resource we need.
type bluecatZone struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	AbsoluteName string `json:"absoluteName"`
}

// GetZoneID resolves a zone name to its Bluecat zone ID, scoped to the given
// configuration and view.
//
// The name is resolved most-specific-first: "a.b.example.com" is tried before
// "b.example.com" and then "example.com", so a delegated subzone wins over its
// parent. Unlike a plain "not found", a transport or authorization failure
// aborts the walk rather than silently falling back to a parent zone.
func (c *Client) GetZoneID(ctx context.Context, zone, configName, viewName string) (int64, error) {
	zone = strings.TrimSuffix(zone, ".")
	if zone == "" {
		return 0, fmt.Errorf("bluecat: zone name is empty")
	}

	cacheKey := strings.Join([]string{configName, viewName, zone}, "\x00")
	if id, ok := c.zones.get(cacheKey); ok {
		return id, nil
	}

	labels := strings.Split(zone, ".")
	for i := range labels {
		candidate := strings.Join(labels[i:], ".")
		if candidate == "" {
			continue
		}

		id, err := c.findZone(ctx, candidate, configName, viewName)
		if err != nil {
			// A real failure — auth, transport, a 5xx — must not degrade
			// into "try the parent zone" and ultimately "no zone found",
			// which is indistinguishable from a genuinely missing zone.
			return 0, fmt.Errorf("bluecat: looking up zone %q: %w", candidate, err)
		}
		if id != 0 {
			c.zones.put(cacheKey, id)
			return id, nil
		}
	}

	return 0, fmt.Errorf("bluecat: no zone found for %q in view %q", zone, viewName)
}

// findZone returns the ID of an exact zone match, or 0 if it does not exist.
func (c *Client) findZone(ctx context.Context, absoluteName, configName, viewName string) (int64, error) {
	// NOTE: the filter syntax below is deliberately mixed. "view.name:'x'" is
	// the form verified against production BAM; "view.name:eq('x')" has not
	// been, and the resourceRecords endpoint rejects view.name entirely with
	// InvalidFilterField. Don't "tidy" these into one style without probing.
	clauses := []string{fmt.Sprintf("absoluteName:eq('%s')", escapeFilterValue(absoluteName))}
	if viewName != "" {
		clauses = append([]string{fmt.Sprintf("view.name:'%s'", escapeFilterValue(viewName))}, clauses...)
	}

	// configName is not applied as a filter clause: whether /zones accepts a
	// "configuration.name" field is unverified, and an InvalidFilterField
	// there would break every lookup. Instead, a configuration mismatch
	// surfaces as the ambiguity error below. See probe P10.
	_ = configName

	query := url.Values{}
	query.Set("filter", strings.Join(clauses, " and "))
	query.Set("limit", "2")

	var resp collection[bluecatZone]
	if err := c.do(ctx, apiRequest{
		Method: http.MethodGet,
		Path:   "/api/v2/zones",
		Query:  query,
		Out:    &resp,
	}); err != nil {
		return 0, err
	}

	if len(resp.Data) == 0 {
		return 0, nil
	}
	if len(resp.Data) > 1 {
		return 0, fmt.Errorf("zone %q is ambiguous: %d matches in view %q (configuration and view scoping may be needed)",
			absoluteName, len(resp.Data), viewName)
	}

	return resp.Data[0].ID, nil
}

// escapeFilterValue escapes a value for interpolation into a single-quoted
// Bluecat filter expression. url encoding handles transport; this handles the
// expression syntax itself.
func escapeFilterValue(s string) string {
	return strings.ReplaceAll(s, "'", "\\'")
}
