package bluecat

import (
	"context"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

const testZone = "utas.edu.au"

const (
	zonesPath   = "/api/v2/zones"
	recordsPath = "/api/v2/zones/42/resourceRecords"
)

// challengeTXT is a realistic ACME challenge record: a 43-character
// base64url key authorization at a multi-label name.
func challengeTXT(text string) libdns.TXT {
	return libdns.TXT{
		Name: "_acme-challenge.test-error-404.its",
		TTL:  300 * time.Second,
		Text: text,
	}
}

const keyAuth = "kAuthZ1gQ7nR4tYuIoP2aS5dFgHjKlZxCvBnM9qWeRt0"

// --- 409 idempotency -------------------------------------------------------

// TestAppendRecords_409SameValueAdopts is the regression test for the
// production failure loop: a retried ACME challenge presents the same key
// authorization, Bluecat rejects it as a duplicate, and issuance must still
// succeed by adopting the record that is already there.
func TestAppendRecords_409SameValueAdopts(t *testing.T) {
	m := newMockBAM(t)
	m.OnAny(http.MethodGet, zonesPath, zoneResponse(42, testZone))
	m.On(http.MethodPost, recordsPath, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusConflict, conflict())
	})
	m.On(http.MethodGet, recordsPath, recordsResponse(
		txtRecord(7, "_acme-challenge.test-error-404.its", keyAuth, testZone),
	))

	p := m.Provider(t)
	got, err := p.AppendRecords(context.Background(), testZone, []libdns.Record{challengeTXT(keyAuth)})
	if err != nil {
		t.Fatalf("AppendRecords should adopt the existing record, got error: %v", err)
	}

	if len(got) != 1 {
		t.Fatalf("expected 1 record, got %d", len(got))
	}
	txt, ok := got[0].(libdns.TXT)
	if !ok {
		t.Fatalf("expected libdns.TXT, got %T", got[0])
	}
	if txt.ProviderData != int64(7) {
		t.Errorf("adopted record should carry the real Bluecat ID 7, got %v", txt.ProviderData)
	}
	if txt.Text != keyAuth {
		t.Errorf("expected text %q, got %q", keyAuth, txt.Text)
	}

	if n := m.CountCalls(http.MethodPost, recordsPath); n != 1 {
		t.Errorf("expected exactly 1 create attempt, got %d", n)
	}
	if n := m.CountCalls(http.MethodGet, recordsPath); n != 1 {
		t.Errorf("expected exactly 1 reconcile lookup, got %d", n)
	}
}

// TestAppendRecords_409QuotedTXTAdopts covers Bluecat handing the value back
// in its wire form, with surrounding quotes.
func TestAppendRecords_409QuotedTXTAdopts(t *testing.T) {
	m := newMockBAM(t)
	m.OnAny(http.MethodGet, zonesPath, zoneResponse(42, testZone))
	m.On(http.MethodPost, recordsPath, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusConflict, conflict())
	})
	m.On(http.MethodGet, recordsPath, recordsResponse(
		txtRecord(9, "_acme-challenge.test-error-404.its", `"`+keyAuth+`"`, testZone),
	))

	p := m.Provider(t)
	got, err := p.AppendRecords(context.Background(), testZone, []libdns.Record{challengeTXT(keyAuth)})
	if err != nil {
		t.Fatalf("quoted TXT should still be adopted, got: %v", err)
	}
	if got[0].(libdns.TXT).ProviderData != int64(9) {
		t.Errorf("expected adopted ID 9, got %v", got[0].(libdns.TXT).ProviderData)
	}
}

// TestAppendRecords_409DifferentValueErrors: a conflict at the same name with
// a different value must not be adopted, since that would report success for
// a record carrying someone else's data.
func TestAppendRecords_409DifferentValueErrors(t *testing.T) {
	m := newMockBAM(t)
	m.OnAny(http.MethodGet, zonesPath, zoneResponse(42, testZone))
	m.On(http.MethodPost, recordsPath, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusConflict, conflict())
	})
	m.On(http.MethodGet, recordsPath, recordsResponse(
		txtRecord(7, "_acme-challenge.test-error-404.its", "some-other-challenge-value", testZone),
	))

	p := m.Provider(t)
	_, err := p.AppendRecords(context.Background(), testZone, []libdns.Record{challengeTXT(keyAuth)})
	if err == nil {
		t.Fatal("expected an error when the existing record holds a different value")
	}
	mustContain(t, err.Error(), "different value", "error")

	if n := m.CountCalls(http.MethodDelete, ""); n != 0 {
		t.Errorf("AppendRecords must never delete an existing record, got %d DELETEs", n)
	}
}

// TestAppendRecords_409NotVisibleErrorsLoudly covers the case where Bluecat
// claims a duplicate but the zone-scoped lookup cannot see it — the signature
// of a record living in a child zone or another view.
func TestAppendRecords_409NotVisibleErrorsLoudly(t *testing.T) {
	m := newMockBAM(t)
	m.OnAny(http.MethodGet, zonesPath, zoneResponse(42, testZone))
	m.On(http.MethodPost, recordsPath, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusConflict, conflict())
	})
	m.On(http.MethodGet, recordsPath, recordsResponse())

	p := m.Provider(t)
	_, err := p.AppendRecords(context.Background(), testZone, []libdns.Record{challengeTXT(keyAuth)})
	if err == nil {
		t.Fatal("expected an error when the conflicting record is not visible")
	}
	mustContain(t, err.Error(), "child zone", "error")
}

// TestCreateOrAdopt_CNAMEConflictNotAdopted: only a value match may be
// adopted, and for single-valued types a mismatch is a hard error.
func TestCreateOrAdopt_CNAMEConflictNotAdopted(t *testing.T) {
	m := newMockBAM(t)
	m.On(http.MethodPost, recordsPath, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusConflict, conflict())
	})
	m.On(http.MethodGet, recordsPath, recordsResponse(map[string]any{
		"id": 11, "type": "AliasRecord", "recordType": "CNAME",
		"name": "www", "absoluteName": "www." + testZone,
		"linkedRecordName": "elsewhere.example.com",
	}))

	c := m.Client(t)
	_, adopted, err := c.CreateOrAdopt(context.Background(), 42, testZone,
		libdns.CNAME{Name: "www", Target: "lb.utas.edu.au"})
	if err == nil {
		t.Fatal("expected an error for a CNAME conflict with a different target")
	}
	if adopted {
		t.Error("a mismatched CNAME must not be adopted")
	}
	if !IsAlreadyExists(err) {
		t.Errorf("error should still satisfy IsAlreadyExists, got %v", err)
	}
}

// --- authentication --------------------------------------------------------

// TestDo_ReauthOn401 verifies a expired session is refreshed and the request
// retried, rather than failing permanently until the process restarts.
func TestDo_ReauthOn401(t *testing.T) {
	m := newMockBAM(t)
	m.On(http.MethodGet, zonesPath,
		func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusUnauthorized, apiErrorBody(401, "Unauthorized", "Unauthorized", "session expired", ""))
		},
		zoneResponse(42, testZone),
	)

	c := m.Client(t)
	c.setCredentials("stale")

	id, err := c.GetZoneID(context.Background(), testZone, "", "external")
	if err != nil {
		t.Fatalf("GetZoneID should recover from an expired session: %v", err)
	}
	if id != 42 {
		t.Errorf("expected zone 42, got %d", id)
	}

	if n := m.CountCalls(http.MethodPost, "/api/v2/sessions"); n != 1 {
		t.Errorf("expected exactly 1 re-authentication, got %d", n)
	}

	calls := m.Calls(http.MethodGet, zonesPath)
	if len(calls) != 2 {
		t.Fatalf("expected 2 zone requests, got %d", len(calls))
	}
}

// TestGetZoneID_401Propagates is the regression test for the masked-auth bug:
// an expired session used to surface as "no zone found", which is
// indistinguishable from a genuinely missing zone.
func TestGetZoneID_401Propagates(t *testing.T) {
	m := newMockBAM(t)
	m.OnAny(http.MethodGet, zonesPath, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusUnauthorized, apiErrorBody(401, "Unauthorized", "Unauthorized", "nope", ""))
	})

	c := m.Client(t)
	_, err := c.GetZoneID(context.Background(), testZone, "", "external")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !IsAuthError(err) {
		t.Errorf("an auth failure must surface as an auth error, got %v", err)
	}
	if strings.Contains(err.Error(), "no zone found") {
		t.Errorf("an auth failure must not be reported as a missing zone: %v", err)
	}
}

// TestRefreshAuth_NoStampede: many goroutines hitting an expired session at
// once must produce exactly one re-authentication, not one per goroutine.
func TestRefreshAuth_NoStampede(t *testing.T) {
	m := newMockBAM(t)

	var sessions int
	var mu sync.Mutex
	m.OnAny(http.MethodPost, "/api/v2/sessions", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		sessions++
		mu.Unlock()
		time.Sleep(50 * time.Millisecond)
		writeJSON(w, http.StatusCreated, map[string]string{
			"basicAuthenticationCredentials": "fresh",
		})
	})

	c := m.Client(t)

	const n = 20
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = c.refreshAuth(context.Background(), 0)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: %v", i, err)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if sessions != 1 {
		t.Errorf("expected exactly 1 authentication across %d concurrent callers, got %d", n, sessions)
	}
}

// TestRefreshAuth_BadCredentialsCooldown: bad credentials must not be retried
// in a tight loop, which is how a service account gets locked out when three
// load balancer nodes all retry at once.
func TestRefreshAuth_BadCredentialsCooldown(t *testing.T) {
	m := newMockBAM(t)
	m.OnAny(http.MethodPost, "/api/v2/sessions", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusUnauthorized, apiErrorBody(401, "Unauthorized", "Unauthorized", "bad password", ""))
	})

	c := m.Client(t)

	if err := c.refreshAuth(context.Background(), 0); err == nil {
		t.Fatal("expected an authentication failure")
	}
	if err := c.refreshAuth(context.Background(), 0); err == nil {
		t.Fatal("expected the second attempt to fail too")
	} else {
		mustContain(t, err.Error(), "cooldown", "second error")
	}

	if n := m.CountCalls(http.MethodPost, "/api/v2/sessions"); n != 1 {
		t.Errorf("cooldown should suppress the second attempt, got %d session requests", n)
	}
}

// TestAuthenticate_RejectsEmptyCredentials: an empty header would otherwise
// yield "Authorization: Basic " on every call — permanent 401s that used to
// be reported as a missing zone.
func TestAuthenticate_RejectsEmptyCredentials(t *testing.T) {
	m := newMockBAM(t)
	m.OnAny(http.MethodPost, "/api/v2/sessions", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusCreated, map[string]string{"apiToken": "tok"})
	})

	c := m.Client(t)
	if _, err := c.authenticate(context.Background()); err == nil {
		t.Fatal("expected an error when Bluecat returns no basicAuthenticationCredentials")
	}
}

// --- retry -----------------------------------------------------------------

func TestDo_RetriesOn503(t *testing.T) {
	m := newMockBAM(t)
	m.On(http.MethodGet, zonesPath,
		func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusServiceUnavailable, nil) },
		func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusServiceUnavailable, nil) },
		zoneResponse(42, testZone),
	)

	c := m.Client(t)
	id, err := c.GetZoneID(context.Background(), testZone, "", "external")
	if err != nil {
		t.Fatalf("expected recovery after transient 503s: %v", err)
	}
	if id != 42 {
		t.Errorf("expected zone 42, got %d", id)
	}
	if n := len(m.Slept()); n != 2 {
		t.Errorf("expected 2 backoff sleeps, got %d", n)
	}
}

// TestDo_UnsafePostNotRetried: replaying a create is exactly how a duplicate
// (and the 409 that follows) gets manufactured.
func TestDo_UnsafePostNotRetried(t *testing.T) {
	m := newMockBAM(t)
	m.OnAny(http.MethodPost, recordsPath, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusServiceUnavailable, nil)
	})

	c := m.Client(t)
	_, err := c.CreateResourceRecord(context.Background(), 42, testZone, challengeTXT(keyAuth))
	if err == nil {
		t.Fatal("expected the 503 to surface")
	}
	if n := m.CountCalls(http.MethodPost, recordsPath); n != 1 {
		t.Errorf("a create must be attempted exactly once, got %d", n)
	}
}

// TestDo_RetryReplaysBody guards the GetBody/replayable-body contract.
func TestDo_RetryReplaysBody(t *testing.T) {
	m := newMockBAM(t)
	m.On(http.MethodPost, "/api/v2/zones/42/deployments",
		func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusServiceUnavailable, nil) },
		func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusCreated, map[string]any{"id": 5, "status": "COMPLETE"})
		},
	)

	c := m.Client(t)
	policy := defaultRetry()
	err := c.do(context.Background(), apiRequest{
		Method: http.MethodPost,
		Path:   "/api/v2/zones/42/deployments",
		Body:   map[string]string{"type": "QuickDeployment"},
		OK:     []int{http.StatusCreated},
		Retry:  &policy,
	})
	if err != nil {
		t.Fatalf("expected success after retry: %v", err)
	}

	calls := m.Calls(http.MethodPost, "/api/v2/zones/42/deployments")
	if len(calls) != 2 {
		t.Fatalf("expected 2 attempts, got %d", len(calls))
	}
	if calls[0].Body != calls[1].Body {
		t.Errorf("retried body differs:\n  first: %q\n second: %q", calls[0].Body, calls[1].Body)
	}
	if calls[1].Body == "" {
		t.Error("retried request sent an empty body; GetBody/replay is broken")
	}
}

func TestDo_ContextCancellation(t *testing.T) {
	m := newMockBAM(t)
	m.OnAny(http.MethodGet, zonesPath, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusServiceUnavailable, nil)
	})

	c := m.Client(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := c.GetZoneID(ctx, testZone, "", "external"); err == nil {
		t.Fatal("expected a context error")
	}
}

func TestRetryAfter(t *testing.T) {
	h := http.Header{}
	h.Set("Retry-After", "3")
	d, ok := retryAfter(h)
	if !ok || d != 3*time.Second {
		t.Errorf("expected 3s, got %v (ok=%v)", d, ok)
	}

	if _, ok := retryAfter(http.Header{}); ok {
		t.Error("absent Retry-After should not report a delay")
	}
}

// --- pagination ------------------------------------------------------------

// TestGetResourceRecords_Paginates is the regression test for the unpaginated
// list: Bluecat's default page is small, so a single request silently
// truncated the zone.
func TestGetResourceRecords_Paginates(t *testing.T) {
	m := newMockBAM(t)

	const total = 250
	all := make([]map[string]any, total)
	for i := range all {
		all[i] = txtRecord(int64(i+1), "rec"+itoa(i), "value", testZone)
	}

	m.OnAny(http.MethodGet, recordsPath, func(w http.ResponseWriter, r *http.Request) {
		limit := atoiDefault(r.URL.Query().Get("limit"), 0)
		offset := atoiDefault(r.URL.Query().Get("offset"), 0)
		if limit == 0 {
			t.Error("request omitted the limit parameter; pagination is not being requested")
			limit = 10
		}
		end := offset + limit
		if end > total {
			end = total
		}
		if offset > total {
			offset = total
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": all[offset:end], "count": total})
	})

	c := m.Client(t)
	got, err := c.GetResourceRecords(context.Background(), 42, testZone)
	if err != nil {
		t.Fatalf("GetResourceRecords: %v", err)
	}
	if len(got) != total {
		t.Errorf("expected all %d records, got %d", total, len(got))
	}
	if n := m.CountCalls(http.MethodGet, recordsPath); n != 3 {
		t.Errorf("expected 3 pages at limit 100, got %d requests", n)
	}
}

// TestFindResourceRecords_ReturnsAllMatches is the regression test for the
// old Data[0] truncation: an RRset with several values must come back whole.
func TestFindResourceRecords_ReturnsAllMatches(t *testing.T) {
	m := newMockBAM(t)
	m.On(http.MethodGet, recordsPath, recordsResponse(
		txtRecord(1, "_acme-challenge", "value-one", testZone),
		txtRecord(2, "_acme-challenge", "value-two", testZone),
		txtRecord(3, "_acme-challenge", "value-three", testZone),
	))

	c := m.Client(t)
	got, err := c.FindResourceRecords(context.Background(), 42, "_acme-challenge", "TXT", testZone)
	if err != nil {
		t.Fatalf("FindResourceRecords: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 matches, got %d", len(got))
	}

	filter := m.Calls(http.MethodGet, recordsPath)[0].Filter()
	mustContain(t, filter, "name:eq('_acme-challenge')", "filter")
	mustContain(t, filter, "recordType:eq('TXT')", "filter")
	if strings.Contains(filter, "view.name") {
		t.Errorf("resourceRecords rejects view.name with InvalidFilterField; filter was %q", filter)
	}
}

func TestListAll_StopsOnShortPage(t *testing.T) {
	m := newMockBAM(t)
	m.On(http.MethodGet, recordsPath, recordsResponse(txtRecord(1, "a", "v", testZone)))

	c := m.Client(t)
	if _, err := c.GetResourceRecords(context.Background(), 42, testZone); err != nil {
		t.Fatalf("GetResourceRecords: %v", err)
	}
	if n := m.CountCalls(http.MethodGet, recordsPath); n != 1 {
		t.Errorf("a short page should end pagination, got %d requests", n)
	}
}

// TestListAll_MaxPagesGuard covers a server that ignores offset, which would
// otherwise loop forever.
func TestListAll_MaxPagesGuard(t *testing.T) {
	m := newMockBAM(t)

	page := make([]map[string]any, 100)
	for i := range page {
		page[i] = txtRecord(int64(i+1), "rec", "value", testZone)
	}
	m.OnAny(http.MethodGet, recordsPath, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"data": page})
	})

	c := m.Client(t)
	_, err := c.GetResourceRecords(context.Background(), 42, testZone)
	if err == nil {
		t.Fatal("expected pagination to give up rather than loop forever")
	}
	mustContain(t, err.Error(), "ignoring offset", "error")
}

// --- delete ----------------------------------------------------------------

// TestDeleteRecords_MatchesOnValue is the regression test for value-blind
// deletion: two concurrent challenges share a name, and cleaning up one must
// not remove the other.
func TestDeleteRecords_MatchesOnValue(t *testing.T) {
	m := newMockBAM(t)
	m.OnAny(http.MethodGet, zonesPath, zoneResponse(42, testZone))
	m.On(http.MethodGet, recordsPath, recordsResponse(
		txtRecord(1, "_acme-challenge", "mine", testZone),
		txtRecord(2, "_acme-challenge", "someone-elses", testZone),
	))

	var deletedIDs []string
	m.OnAny(http.MethodDelete, "/api/v2/resourceRecords/1", func(w http.ResponseWriter, r *http.Request) {
		deletedIDs = append(deletedIDs, "1")
		w.WriteHeader(http.StatusNoContent)
	})
	m.OnAny(http.MethodDelete, "/api/v2/resourceRecords/2", func(w http.ResponseWriter, r *http.Request) {
		deletedIDs = append(deletedIDs, "2")
		w.WriteHeader(http.StatusNoContent)
	})

	p := m.Provider(t)
	deleted, err := p.DeleteRecords(context.Background(), testZone, []libdns.Record{
		libdns.TXT{Name: "_acme-challenge", Text: "mine"},
	})
	if err != nil {
		t.Fatalf("DeleteRecords: %v", err)
	}
	if len(deleted) != 1 {
		t.Errorf("expected 1 deleted record, got %d", len(deleted))
	}
	if len(deletedIDs) != 1 || deletedIDs[0] != "1" {
		t.Errorf("expected only record 1 to be deleted, got %v", deletedIDs)
	}
}

// TestDeleteRecords_TypeErasedRR covers what certmagic actually passes: a
// libdns.RR, because RR() strips ProviderData before cleanup ever runs.
func TestDeleteRecords_TypeErasedRR(t *testing.T) {
	m := newMockBAM(t)
	m.OnAny(http.MethodGet, zonesPath, zoneResponse(42, testZone))
	m.On(http.MethodGet, recordsPath, recordsResponse(
		txtRecord(1, "_acme-challenge.test-error-404.its", keyAuth, testZone),
		txtRecord(2, "_acme-challenge.test-error-404.its", "other", testZone),
	))

	var deleted []string
	m.OnAny(http.MethodDelete, "/api/v2/resourceRecords/1", func(w http.ResponseWriter, r *http.Request) {
		deleted = append(deleted, "1")
		w.WriteHeader(http.StatusNoContent)
	})

	p := m.Provider(t)
	got, err := p.DeleteRecords(context.Background(), testZone, []libdns.Record{
		libdns.RR{Name: "_acme-challenge.test-error-404.its", Type: "TXT", Data: keyAuth},
	})
	if err != nil {
		t.Fatalf("DeleteRecords with a type-erased RR: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("expected 1 deleted record, got %d", len(got))
	}
	if len(deleted) != 1 {
		t.Errorf("expected exactly record 1 deleted, got %v", deleted)
	}
}

// TestDeleteRecords_EmptyDataWildcard: per the libdns contract, an empty Data
// matches every value at that name.
func TestDeleteRecords_EmptyDataWildcard(t *testing.T) {
	m := newMockBAM(t)
	m.OnAny(http.MethodGet, zonesPath, zoneResponse(42, testZone))
	m.On(http.MethodGet, recordsPath, recordsResponse(
		txtRecord(1, "_acme-challenge", "one", testZone),
		txtRecord(2, "_acme-challenge", "two", testZone),
	))
	m.OnAny(http.MethodDelete, "/api/v2/resourceRecords/1", noContent)
	m.OnAny(http.MethodDelete, "/api/v2/resourceRecords/2", noContent)

	p := m.Provider(t)
	deleted, err := p.DeleteRecords(context.Background(), testZone, []libdns.Record{
		libdns.RR{Name: "_acme-challenge", Type: "TXT"},
	})
	if err != nil {
		t.Fatalf("DeleteRecords: %v", err)
	}
	if len(deleted) != 1 {
		t.Errorf("expected the input record reported once, got %d", len(deleted))
	}
	if n := m.CountCalls(http.MethodDelete, ""); n != 2 {
		t.Errorf("expected both values deleted, got %d DELETEs", n)
	}
}

// TestDeleteRecords_NotFoundIsNotADeletion: a record that was already gone is
// not an error, but it must not be reported as deleted either.
func TestDeleteRecords_NotFoundIsNotADeletion(t *testing.T) {
	m := newMockBAM(t)
	m.OnAny(http.MethodGet, zonesPath, zoneResponse(42, testZone))
	m.On(http.MethodGet, recordsPath, recordsResponse())

	p := m.Provider(t)
	deleted, err := p.DeleteRecords(context.Background(), testZone, []libdns.Record{
		libdns.TXT{Name: "_acme-challenge", Text: "gone"},
	})
	if err != nil {
		t.Fatalf("a missing record should not be an error: %v", err)
	}
	if len(deleted) != 0 {
		t.Errorf("nothing was deleted, so nothing should be reported: %v", deleted)
	}
}

// TestDeleteResourceRecordByID_404IsSuccess covers concurrent cleanups racing
// on the same record.
func TestDeleteResourceRecordByID_404IsSuccess(t *testing.T) {
	m := newMockBAM(t)
	m.OnAny(http.MethodDelete, "/api/v2/resourceRecords/5", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotFound, apiErrorBody(404, "Not Found", "NotFound", "gone", ""))
	})

	c := m.Client(t)
	if err := c.DeleteResourceRecordByID(context.Background(), 5); err != nil {
		t.Errorf("deleting an already-absent record should succeed, got %v", err)
	}
}

// --- SetRecords ------------------------------------------------------------

// TestSetRecords_DoesNotTouchOtherNames is the regression test for the
// zone-wiping bug: SetRecords used to delete every record whose name:type was
// absent from the input.
func TestSetRecords_DoesNotTouchOtherNames(t *testing.T) {
	m := newMockBAM(t)
	m.OnAny(http.MethodGet, zonesPath, zoneResponse(42, testZone))
	// Only the www/A RRset is ever queried.
	m.On(http.MethodGet, recordsPath, recordsResponse())
	m.OnAny(http.MethodPost, recordsPath, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusCreated, map[string]any{
			"id": 99, "type": "HostRecord", "recordType": "A",
			"name": "www", "absoluteName": "www." + testZone,
			"addresses": []map[string]string{{"address": "192.0.2.1"}},
		})
	})

	p := m.Provider(t)
	_, err := p.SetRecords(context.Background(), testZone, []libdns.Record{
		libdns.Address{Name: "www", IP: netip.MustParseAddr("192.0.2.1")},
	})
	if err != nil {
		t.Fatalf("SetRecords: %v", err)
	}

	if n := m.CountCalls(http.MethodDelete, ""); n != 0 {
		t.Errorf("SetRecords must not delete records outside the requested RRset, got %d DELETEs", n)
	}

	// The lookup must be scoped to the one RRset being set.
	filter := m.Calls(http.MethodGet, recordsPath)[0].Filter()
	mustContain(t, filter, "name:eq('www')", "filter")
}

// TestSetRecords_MultipleValuesOneKey: each existing record is deleted at most
// once, no matter how many input records share the RRset.
func TestSetRecords_MultipleValuesOneKey(t *testing.T) {
	m := newMockBAM(t)
	m.OnAny(http.MethodGet, zonesPath, zoneResponse(42, testZone))
	m.On(http.MethodGet, recordsPath, recordsResponse(
		txtRecord(1, "multi", "old-value", testZone),
	))

	deletes := map[string]int{}
	m.OnAny(http.MethodDelete, "/api/v2/resourceRecords/1", func(w http.ResponseWriter, r *http.Request) {
		deletes["1"]++
		w.WriteHeader(http.StatusNoContent)
	})

	var created int
	m.OnAny(http.MethodPost, recordsPath, func(w http.ResponseWriter, r *http.Request) {
		created++
		writeJSON(w, http.StatusCreated, txtRecord(int64(100+created), "multi", "new", testZone))
	})

	p := m.Provider(t)
	updated, err := p.SetRecords(context.Background(), testZone, []libdns.Record{
		libdns.TXT{Name: "multi", Text: "new-one"},
		libdns.TXT{Name: "multi", Text: "new-two"},
	})
	if err != nil {
		t.Fatalf("SetRecords: %v", err)
	}
	if len(updated) != 2 {
		t.Errorf("expected 2 records, got %d", len(updated))
	}
	if deletes["1"] != 1 {
		t.Errorf("the existing record should be deleted exactly once, got %d", deletes["1"])
	}
	if n := m.CountCalls(http.MethodGet, recordsPath); n != 1 {
		t.Errorf("the RRset should be read once, got %d reads", n)
	}
}

// TestSetRecords_KeepsMatchingValue: a value already present is left in place
// rather than deleted and recreated, which would briefly empty the name.
func TestSetRecords_KeepsMatchingValue(t *testing.T) {
	m := newMockBAM(t)
	m.OnAny(http.MethodGet, zonesPath, zoneResponse(42, testZone))
	m.On(http.MethodGet, recordsPath, recordsResponse(
		txtRecord(1, "keep", "same-value", testZone),
	))
	m.OnAny(http.MethodPost, recordsPath, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusConflict, conflict())
	})
	m.On(http.MethodGet, recordsPath, recordsResponse(
		txtRecord(1, "keep", "same-value", testZone),
	))

	p := m.Provider(t)
	updated, err := p.SetRecords(context.Background(), testZone, []libdns.Record{
		libdns.TXT{Name: "keep", Text: "same-value"},
	})
	if err != nil {
		t.Fatalf("SetRecords: %v", err)
	}
	if len(updated) != 1 {
		t.Fatalf("expected 1 record, got %d", len(updated))
	}
	if n := m.CountCalls(http.MethodDelete, ""); n != 0 {
		t.Errorf("an unchanged value should not be deleted, got %d DELETEs", n)
	}
}

// --- zone lookup -----------------------------------------------------------

func TestGetZoneID_ScopesToView(t *testing.T) {
	m := newMockBAM(t)
	m.On(http.MethodGet, zonesPath, zoneResponse(42, testZone))

	c := m.Client(t)
	id, err := c.GetZoneID(context.Background(), testZone, "", "external")
	if err != nil {
		t.Fatalf("GetZoneID: %v", err)
	}
	if id != 42 {
		t.Errorf("expected 42, got %d", id)
	}

	filter := m.Calls(http.MethodGet, zonesPath)[0].Filter()
	mustContain(t, filter, "view.name:'external'", "filter")
	mustContain(t, filter, "absoluteName:eq('"+testZone+"')", "filter")
}

// TestGetZoneID_WalksToParent covers a challenge name under a zone that is not
// itself delegated.
func TestGetZoneID_WalksToParent(t *testing.T) {
	m := newMockBAM(t)
	m.On(http.MethodGet, zonesPath,
		recordsResponse(),               // sub.utas.edu.au: no match
		zoneResponse(42, "utas.edu.au"), // utas.edu.au: match
	)

	c := m.Client(t)
	id, err := c.GetZoneID(context.Background(), "sub.utas.edu.au", "", "external")
	if err != nil {
		t.Fatalf("GetZoneID: %v", err)
	}
	if id != 42 {
		t.Errorf("expected the parent zone 42, got %d", id)
	}
}

func TestGetZoneID_Caches(t *testing.T) {
	m := newMockBAM(t)
	m.OnAny(http.MethodGet, zonesPath, zoneResponse(42, testZone))

	c := m.Client(t)
	for i := 0; i < 3; i++ {
		if _, err := c.GetZoneID(context.Background(), testZone, "", "external"); err != nil {
			t.Fatalf("GetZoneID: %v", err)
		}
	}
	if n := m.CountCalls(http.MethodGet, zonesPath); n != 1 {
		t.Errorf("expected the zone ID to be cached, got %d lookups", n)
	}
}

func TestGetZoneID_AmbiguousIsAnError(t *testing.T) {
	m := newMockBAM(t)
	m.OnAny(http.MethodGet, zonesPath, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"data": []map[string]any{
			{"id": 1, "absoluteName": testZone},
			{"id": 2, "absoluteName": testZone},
		}})
	})

	c := m.Client(t)
	if _, err := c.GetZoneID(context.Background(), testZone, "", ""); err == nil {
		t.Fatal("an ambiguous zone must be an error, not a silent pick of the first match")
	}
}

func TestEscapeFilterValue(t *testing.T) {
	if got := escapeFilterValue("o'brien"); got != `o\'brien` {
		t.Errorf("expected the quote to be escaped, got %q", got)
	}
}

// --- deploy scheduling -----------------------------------------------------

// TestScheduleDeploy_CapsDebounce is the regression test for deploy
// starvation: a steady stream of writes used to reset the debounce timer
// forever, so the deploy never ran and records never reached DNS.
func TestScheduleDeploy_CapsDebounce(t *testing.T) {
	m := newMockBAM(t)

	deployed := make(chan struct{}, 1)
	m.OnAny(http.MethodPost, "/api/v2/zones/42/deployments", func(w http.ResponseWriter, r *http.Request) {
		select {
		case deployed <- struct{}{}:
		default:
		}
		writeJSON(w, http.StatusCreated, map[string]any{"id": 1, "status": "COMPLETE"})
	})

	p := m.Provider(t)
	p.DisableDeploy = false
	p.DeployDelay = 20 * time.Millisecond
	p.MaxDeployDelay = 60 * time.Millisecond

	client := p.client
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Keep resetting the timer faster than DeployDelay for well past
		// MaxDeployDelay.
		deadline := time.Now().Add(300 * time.Millisecond)
		for time.Now().Before(deadline) {
			p.scheduleDeploy(client, 42)
			time.Sleep(5 * time.Millisecond)
		}
	}()

	select {
	case <-deployed:
	case <-time.After(2 * time.Second):
		t.Fatal("deploy never fired: continuous writes starved the debounce timer")
	}
	<-done
}

// TestScheduleDeploy_CoalescesWaiters: concurrent challenges share one deploy,
// and every caller waits for it.
func TestScheduleDeploy_CoalescesWaiters(t *testing.T) {
	m := newMockBAM(t)

	var deploys int
	var mu sync.Mutex
	m.OnAny(http.MethodPost, "/api/v2/zones/42/deployments", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		deploys++
		mu.Unlock()
		writeJSON(w, http.StatusCreated, map[string]any{"id": 1, "status": "COMPLETE"})
	})

	p := m.Provider(t)
	p.DisableDeploy = false
	p.DeployDelay = 20 * time.Millisecond

	const n = 10
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			wait := p.scheduleDeploy(p.client, 42)
			errs[i] = wait(context.Background())
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("waiter %d: %v", i, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if deploys != 1 {
		t.Errorf("expected %d writes to coalesce into 1 deploy, got %d", n, deploys)
	}
}

// TestAppendRecords_ReturnsDeployError: a record that was written but not
// deployed is not live, and the caller must hear about it.
func TestAppendRecords_ReturnsDeployError(t *testing.T) {
	m := newMockBAM(t)
	m.OnAny(http.MethodGet, zonesPath, zoneResponse(42, testZone))
	m.OnAny(http.MethodPost, recordsPath, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusCreated, txtRecord(1, "_acme-challenge", keyAuth, testZone))
	})
	m.OnAny(http.MethodPost, "/api/v2/zones/42/deployments", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusInternalServerError, apiErrorBody(500, "Server Error", "Internal", "boom", ""))
	})

	p := m.Provider(t)
	p.DisableDeploy = false
	p.DeployDelay = 10 * time.Millisecond

	_, err := p.AppendRecords(context.Background(), testZone,
		[]libdns.Record{libdns.TXT{Name: "_acme-challenge", Text: keyAuth}})
	if err == nil {
		t.Fatal("expected a deploy failure to surface")
	}
	mustContain(t, err.Error(), "deploy failed", "error")
}

func TestDeployZone_PollsUntilComplete(t *testing.T) {
	m := newMockBAM(t)
	m.OnAny(http.MethodPost, "/api/v2/zones/42/deployments", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusAccepted, map[string]any{"id": 77, "status": "QUEUED"})
	})
	m.On(http.MethodGet, "/api/v2/deployments/77",
		func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{"id": 77, "status": "RUNNING"})
		},
		func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{"id": 77, "status": "COMPLETED"})
		},
	)

	c := m.Client(t)
	if err := c.DeployZone(context.Background(), 42); err != nil {
		t.Fatalf("DeployZone: %v", err)
	}
	if n := m.CountCalls(http.MethodGet, "/api/v2/deployments/77"); n != 2 {
		t.Errorf("expected 2 polls, got %d", n)
	}
}

func TestDeployZone_FailedStatus(t *testing.T) {
	m := newMockBAM(t)
	m.OnAny(http.MethodPost, "/api/v2/zones/42/deployments", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusAccepted, map[string]any{"id": 77})
	})
	m.OnAny(http.MethodGet, "/api/v2/deployments/77", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"id": 77, "status": "FAILED"})
	})

	c := m.Client(t)
	err := c.DeployZone(context.Background(), 42)
	if err == nil {
		t.Fatal("expected a failed deployment to be an error")
	}
	mustContain(t, err.Error(), "FAILED", "error")
}

// --- concurrency -----------------------------------------------------------

// TestConcurrentAppendSameName exercises the keyed RRset lock and the
// 409-adoption path together under -race.
func TestConcurrentAppendSameName(t *testing.T) {
	m := newMockBAM(t)
	m.OnAny(http.MethodGet, zonesPath, zoneResponse(42, testZone))

	var mu sync.Mutex
	stored := map[string]int64{}
	var nextID int64 = 100

	m.OnAny(http.MethodPost, recordsPath, func(w http.ResponseWriter, r *http.Request) {
		var body BluecatResourceRecord
		_ = decodeBody(r, &body)

		mu.Lock()
		defer mu.Unlock()
		if _, exists := stored[body.Text]; exists {
			writeJSON(w, http.StatusConflict, conflict())
			return
		}
		nextID++
		stored[body.Text] = nextID
		writeJSON(w, http.StatusCreated, txtRecord(nextID, body.Name, body.Text, testZone))
	})

	m.OnAny(http.MethodGet, recordsPath, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		var out []map[string]any
		for text, id := range stored {
			out = append(out, txtRecord(id, "_acme-challenge", text, testZone))
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": out, "count": len(out)})
	})

	p := m.Provider(t)

	const n = 10
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Half the goroutines present a duplicate value on purpose.
			text := "value-" + itoa(i%5)
			_, errs[i] = p.AppendRecords(context.Background(), testZone,
				[]libdns.Record{libdns.TXT{Name: "_acme-challenge", Text: text}})
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: every append should create or adopt, got: %v", i, err)
		}
	}
}

// --- matching --------------------------------------------------------------

func TestMatchesRecord(t *testing.T) {
	tests := []struct {
		name     string
		input    libdns.RR
		existing libdns.RR
		want     bool
	}{
		{
			name:     "exact match",
			input:    libdns.RR{Name: "test", Type: "A", TTL: 300 * time.Second, Data: "192.0.2.1"},
			existing: libdns.RR{Name: "test", Type: "A", TTL: 300 * time.Second, Data: "192.0.2.1"},
			want:     true,
		},
		{
			name:     "different name",
			input:    libdns.RR{Name: "test1", Type: "A", Data: "192.0.2.1"},
			existing: libdns.RR{Name: "test2", Type: "A", Data: "192.0.2.1"},
			want:     false,
		},
		{
			name:     "empty type is a wildcard",
			input:    libdns.RR{Name: "test", Data: "192.0.2.1"},
			existing: libdns.RR{Name: "test", Type: "A", Data: "192.0.2.1"},
			want:     true,
		},
		{
			name:     "empty TTL is a wildcard",
			input:    libdns.RR{Name: "test", Type: "A", Data: "192.0.2.1"},
			existing: libdns.RR{Name: "test", Type: "A", TTL: 300 * time.Second, Data: "192.0.2.1"},
			want:     true,
		},
		{
			name:     "empty data is a wildcard",
			input:    libdns.RR{Name: "test", Type: "A", TTL: 300 * time.Second},
			existing: libdns.RR{Name: "test", Type: "A", TTL: 300 * time.Second, Data: "192.0.2.1"},
			want:     true,
		},
		{
			name:     "different data",
			input:    libdns.RR{Name: "test", Type: "TXT", Data: "one"},
			existing: libdns.RR{Name: "test", Type: "TXT", Data: "two"},
			want:     false,
		},
		{
			name:     "TXT quoting is normalised",
			input:    libdns.RR{Name: "test", Type: "TXT", Data: keyAuth},
			existing: libdns.RR{Name: "test", Type: "TXT", Data: `"` + keyAuth + `"`},
			want:     true,
		},
		{
			name:     "CNAME target is case and dot insensitive",
			input:    libdns.RR{Name: "www", Type: "CNAME", Data: "LB.utas.edu.au."},
			existing: libdns.RR{Name: "www", Type: "CNAME", Data: "lb.utas.edu.au"},
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchesRecord(tt.input, tt.existing); got != tt.want {
				t.Errorf("matchesRecord() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNormalizeRecordName(t *testing.T) {
	tests := []struct{ name, zone, want string }{
		{"_acme-challenge", "utas.edu.au", "_acme-challenge"},
		{"_acme-challenge.utas.edu.au", "utas.edu.au", "_acme-challenge"},
		{"_acme-challenge.utas.edu.au.", "utas.edu.au.", "_acme-challenge"},
		{"_acme-challenge.test-error-404.its.utas.edu.au", "utas.edu.au", "_acme-challenge.test-error-404.its"},
		{"utas.edu.au", "utas.edu.au", "@"},
		{"@", "utas.edu.au", "@"},
		{"", "utas.edu.au", "@"},
		{"UTAS.EDU.AU", "utas.edu.au", "@"},
	}

	for _, tt := range tests {
		if got := normalizeRecordName(tt.name, tt.zone); got != tt.want {
			t.Errorf("normalizeRecordName(%q, %q) = %q, want %q", tt.name, tt.zone, got, tt.want)
		}
	}
}

// TestConvertLibdnsToBluecat_TypeErasedTXT: an RR carrying a TXT value must
// become a TXTRecord with a text field, not a GenericRecord with rdata. They
// are different objects in Bluecat, and the TXT lookup path only finds one.
func TestConvertLibdnsToBluecat_TypeErasedTXT(t *testing.T) {
	got, err := convertLibdnsToBluecat(
		libdns.RR{Name: "_acme-challenge", Type: "TXT", TTL: 300 * time.Second, Data: keyAuth},
		testZone)
	if err != nil {
		t.Fatalf("convertLibdnsToBluecat: %v", err)
	}
	if got.Type != "TXTRecord" {
		t.Errorf("expected TXTRecord, got %q", got.Type)
	}
	if got.Text != keyAuth {
		t.Errorf("expected text %q, got %q (rdata=%q)", keyAuth, got.Text, got.RData)
	}
}

func TestConvertRoundTrip(t *testing.T) {
	records := []libdns.Record{
		libdns.TXT{Name: "_acme-challenge", TTL: 300 * time.Second, Text: keyAuth},
		libdns.Address{Name: "www", TTL: 300 * time.Second, IP: netip.MustParseAddr("192.0.2.1")},
		libdns.Address{Name: "www6", TTL: 300 * time.Second, IP: netip.MustParseAddr("2001:db8::1")},
		libdns.CNAME{Name: "alias", TTL: 300 * time.Second, Target: "lb.utas.edu.au"},
		libdns.MX{Name: "@", TTL: 300 * time.Second, Preference: 10, Target: "mail.utas.edu.au"},
	}

	for _, rec := range records {
		bc, err := convertLibdnsToBluecat(rec, testZone)
		if err != nil {
			t.Errorf("%T: convert to bluecat: %v", rec, err)
			continue
		}
		bc.ID = 1
		back, err := convertBluecatToLibdns(bc, testZone)
		if err != nil {
			t.Errorf("%T: convert back: %v", rec, err)
			continue
		}
		if !recordValueEquals(rec, bc, testZone) {
			t.Errorf("%T: value did not survive the round trip: %+v -> %+v", rec, rec, back)
		}
	}
}

func TestIsAlreadyExists(t *testing.T) {
	err := parseAPIError("POST", "/x", http.StatusConflict, mustJSON(conflict()))
	if !IsAlreadyExists(err) {
		t.Error("the production conflict envelope should satisfy IsAlreadyExists")
	}
	if IsNotFound(err) || IsAuthError(err) || IsRetryable(err) {
		t.Error("a conflict is not a not-found, auth, or retryable error")
	}

	// An unparseable body still classifies by status.
	raw := parseAPIError("POST", "/x", http.StatusConflict, []byte("<html>gateway</html>"))
	if !IsAlreadyExists(raw) {
		t.Error("a bare 409 should still satisfy IsAlreadyExists")
	}
	if raw.RawBody == "" {
		t.Error("an unparseable body should be retained for diagnosis")
	}
}

func noContent(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }

// TestScheduleDeploy_NoDoubleFire is the regression test for a double close
// of the batch's done channel.
//
// The window: the debounce timer has fired and its callback is blocked on
// deployMu, while a new write holds deployMu and finds the batch still in the
// map. Resetting the timer then would run the callback a second time. The
// test holds deployMu itself so it can open that window deterministically.
func TestScheduleDeploy_NoDoubleFire(t *testing.T) {
	m := newMockBAM(t)
	m.OnAny(http.MethodPost, "/api/v2/zones/42/deployments", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusCreated, map[string]any{"id": 1, "status": "COMPLETE"})
	})

	p := m.Provider(t)
	p.DisableDeploy = false
	delay := 5 * time.Millisecond
	// Both must be short, or the first batch arms with the multi-second
	// default and never fires inside the window.
	p.DeployDelay = delay
	p.MaxDeployDelay = delay

	// Arm the batch.
	first := p.scheduleDeploy(p.client, 42)

	// Hold the lock past the delay so the callback fires and then blocks.
	p.deployMu.Lock()
	time.Sleep(10 * delay)

	// Inside the window: the batch is still in the map, its timer has fired.
	second := p.scheduleDeployLocked(p.client, 42, delay, delay)
	p.deployMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := first(ctx); err != nil {
		t.Errorf("first batch: %v", err)
	}
	if err := second(ctx); err != nil {
		t.Errorf("second batch: %v", err)
	}

	// Give a wrongly re-armed timer time to fire a second time and panic.
	time.Sleep(10 * delay)
}
