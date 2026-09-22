// Package bluecat implements a DNS record management client compatible
// with the libdns interfaces for Bluecat Address Manager.
package bluecat

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/libdns/libdns"
)

const (
	defaultDeployDelay = 5 * time.Second
	minMaxDeployDelay  = 30 * time.Second
)

// Provider facilitates DNS record manipulation with Bluecat Address Manager.
type Provider struct {
	// ServerURL is the base URL of the Bluecat Address Manager server
	// (e.g., "https://bluecat.example.com")
	ServerURL string `json:"server_url,omitempty"`

	// Username for authenticating with the Bluecat API
	Username string `json:"username,omitempty"`

	// Password for authenticating with the Bluecat API
	Password string `json:"password,omitempty"`

	// Configuration name in Bluecat (optional, defaults to first available)
	ConfigurationName string `json:"configuration_name,omitempty"`

	// View name in Bluecat (optional, defaults to first available)
	ViewName string `json:"view_name,omitempty"`

	// DeployDelay is how long to wait after the last record write before
	// issuing a QuickDeploy to Bluecat. This debounces rapid sequential
	// writes (e.g. multiple concurrent ACME DNS-01 challenges) into a
	// single deploy call, avoiding Bluecat timeouts.
	//
	// Defaults to 5 seconds when zero or unset.
	DeployDelay time.Duration `json:"deploy_delay,omitempty"`

	// MaxDeployDelay caps how long debouncing can postpone a deploy. Without
	// a cap, a steady stream of writes — a bulk renewal, say — resets the
	// debounce timer indefinitely and the deploy never runs at all.
	//
	// Defaults to four times DeployDelay, or 30 seconds, whichever is larger.
	MaxDeployDelay time.Duration `json:"max_deploy_delay,omitempty"`

	// DisableDeploy suppresses automatic deployment entirely. Records are
	// written to Bluecat but not pushed to the DNS servers, so callers must
	// arrange deployment themselves. Advanced use only.
	DisableDeploy bool `json:"disable_deploy,omitempty"`

	// Logger receives operational detail: adopted duplicate records,
	// re-authentication, deploy coalescing. Defaults to discarding output.
	Logger *slog.Logger `json:"-"`

	clientMu sync.Mutex
	client   *Client

	deployMu       sync.Mutex
	pendingDeploys map[int64]*deployState

	// rrsets serialises read-modify-write cycles on a single RRset within
	// this process. Cross-node races are handled by CreateOrAdopt instead,
	// since a libdns provider cannot take a cluster-wide lock.
	rrsets keyedMutex
}

func (p *Provider) logger() *slog.Logger {
	if p.Logger != nil {
		return p.Logger
	}
	return discardLogger
}

// discardLogger drops everything. slog.DiscardHandler would do, but it needs
// Go 1.24 and this module targets 1.21.
var discardLogger = slog.New(discardHandler{})

type discardHandler struct{}

func (discardHandler) Enabled(context.Context, slog.Level) bool  { return false }
func (discardHandler) Handle(context.Context, slog.Record) error { return nil }
func (h discardHandler) WithAttrs([]slog.Attr) slog.Handler      { return h }
func (h discardHandler) WithGroup(string) slog.Handler           { return h }

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	client, zoneID, err := p.resolveZone(ctx, zone)
	if err != nil {
		return nil, err
	}

	records, err := client.GetResourceRecords(ctx, zoneID, zone)
	if err != nil {
		return nil, fmt.Errorf("failed to get resource records: %w", err)
	}

	return records, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
//
// A record that already exists in Bluecat with the value being written is
// adopted rather than treated as an error. Bluecat rejects duplicates with 409
// ResourceAlreadyExists, and during ACME that happens routinely: a retried
// challenge presents the same key authorization, and another cluster node may
// have written the identical record first. The requested state already holds
// in both cases.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	client, zoneID, err := p.resolveZone(ctx, zone)
	if err != nil {
		return nil, err
	}

	created := make([]libdns.Record, 0, len(records))
	for _, record := range records {
		rec, adopted, err := p.createLocked(ctx, client, zoneID, zone, record)
		if err != nil {
			// Deploy whatever landed before the failure; leaving written
			// records undeployed helps nobody.
			p.scheduleDeploy(client, zoneID)
			return created, fmt.Errorf("failed to create record: %w", err)
		}
		if adopted {
			rr := record.RR()
			p.logger().Info("adopted existing bluecat record",
				"zone", zone, "name", rr.Name, "type", rr.Type)
		}
		created = append(created, rec)
	}

	wait := p.scheduleDeploy(client, zoneID)
	if err := wait(ctx); err != nil {
		return created, fmt.Errorf("records written but deploy failed: %w", err)
	}

	return created, nil
}

// SetRecords sets the records in the zone, either by updating existing records
// or creating new ones. It returns the updated records.
//
// Only the (name, type) pairs present in records are touched; every other
// record in the zone is left alone, per the libdns contract.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	client, zoneID, err := p.resolveZone(ctx, zone)
	if err != nil {
		return nil, err
	}

	// Group by RRset so each (name, type) is replaced exactly once. Doing it
	// per-record would delete the same existing records repeatedly.
	type rrsetKey struct{ name, typ string }
	var order []rrsetKey
	byKey := make(map[rrsetKey][]libdns.Record)
	for _, rec := range records {
		rr := rec.RR()
		key := rrsetKey{normalizeRecordName(rr.Name, zone), rr.Type}
		if _, seen := byKey[key]; !seen {
			order = append(order, key)
		}
		byKey[key] = append(byKey[key], rec)
	}

	updated := make([]libdns.Record, 0, len(records))
	for _, key := range order {
		set, err := p.setRRset(ctx, client, zoneID, zone, key.name, key.typ, byKey[key])
		updated = append(updated, set...)
		if err != nil {
			p.scheduleDeploy(client, zoneID)
			return updated, err
		}
	}

	wait := p.scheduleDeploy(client, zoneID)
	if err := wait(ctx); err != nil {
		return updated, fmt.Errorf("records written but deploy failed: %w", err)
	}

	return updated, nil
}

// setRRset replaces every record at one (name, type) with the given set.
func (p *Provider) setRRset(ctx context.Context, client *Client, zoneID int64, zone, name, recType string, want []libdns.Record) ([]libdns.Record, error) {
	unlock := p.rrsets.lock(rrsetKeyOf(zoneID, name, recType))
	defer unlock()

	existing, err := client.FindResourceRecords(ctx, zoneID, name, recType, zone)
	if err != nil {
		return nil, fmt.Errorf("failed to get existing records for %s %s: %w", recType, name, err)
	}

	// Keep records whose value we're about to write; delete the rest. This
	// avoids a delete/create cycle that would briefly leave the name empty.
	keep := make(map[int64]bool)
	for _, w := range want {
		for _, e := range existing {
			if recordValueEquals(w, e, zone) {
				keep[e.ID] = true
				break
			}
		}
	}

	for _, e := range existing {
		if keep[e.ID] {
			continue
		}
		if err := client.DeleteResourceRecordByID(ctx, e.ID); err != nil {
			return nil, fmt.Errorf("failed to delete record %d: %w", e.ID, err)
		}
	}

	out := make([]libdns.Record, 0, len(want))
	for _, w := range want {
		rec, _, err := client.CreateOrAdopt(ctx, zoneID, zone, w)
		if err != nil {
			return out, fmt.Errorf("failed to create/update record: %w", err)
		}
		out = append(out, rec)
	}

	return out, nil
}

// DeleteRecords deletes the specified records from the zone. It returns the
// records that were actually deleted.
//
// Records are matched on name, type and value; empty Type, TTL or Data fields
// act as wildcards, per the libdns contract. Matching on value matters: two
// concurrent ACME challenges can hold different TXT values at the same
// _acme-challenge name, and cleaning up one must not remove the other.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	client, zoneID, err := p.resolveZone(ctx, zone)
	if err != nil {
		return nil, err
	}

	var deleted []libdns.Record
	var deletedAny bool

	for _, record := range records {
		got, err := p.deleteOne(ctx, client, zoneID, zone, record)
		if got {
			deleted = append(deleted, record)
			deletedAny = true
		}
		if err != nil {
			if deletedAny {
				p.scheduleDeploy(client, zoneID)
			}
			return deleted, err
		}
	}

	if deletedAny {
		// Cleanup is best-effort and runs on a budget the caller needs for
		// other work, so schedule the deploy but don't block on it.
		p.scheduleDeploy(client, zoneID)
	}

	return deleted, nil
}

// deleteOne removes every Bluecat record matching one libdns record. It
// reports whether anything was actually deleted.
func (p *Provider) deleteOne(ctx context.Context, client *Client, zoneID int64, zone string, record libdns.Record) (bool, error) {
	rr := record.RR()
	name := normalizeRecordName(rr.Name, zone)

	unlock := p.rrsets.lock(rrsetKeyOf(zoneID, name, rr.Type))
	defer unlock()

	candidates, err := client.FindResourceRecords(ctx, zoneID, name, rr.Type, zone)
	if err != nil {
		return false, fmt.Errorf("failed to look up %s %s: %w", rr.Type, rr.Name, err)
	}

	var matched []BluecatResourceRecord
	for _, candidate := range candidates {
		converted, convErr := convertBluecatToLibdns(candidate, zone)
		if convErr != nil {
			continue
		}
		if matchesRecord(rr, converted.RR()) {
			matched = append(matched, candidate)
		}
	}

	if len(matched) == 0 {
		// Already absent. Not an error, but not a deletion either, so it is
		// omitted from the returned set.
		p.logger().Debug("no bluecat record matched for deletion",
			"zone", zone, "name", rr.Name, "type", rr.Type,
			"candidates", len(candidates))
		return false, nil
	}

	var deletedAny bool
	for _, m := range matched {
		if err := client.DeleteResourceRecordByID(ctx, m.ID); err != nil {
			return deletedAny, fmt.Errorf("failed to delete record %d (%s %s): %w", m.ID, rr.Type, rr.Name, err)
		}
		deletedAny = true
	}

	return deletedAny, nil
}

// createLocked creates one record while holding that RRset's lock.
func (p *Provider) createLocked(ctx context.Context, client *Client, zoneID int64, zone string, record libdns.Record) (libdns.Record, bool, error) {
	rr := record.RR()
	unlock := p.rrsets.lock(rrsetKeyOf(zoneID, normalizeRecordName(rr.Name, zone), rr.Type))
	defer unlock()

	return client.CreateOrAdopt(ctx, zoneID, zone, record)
}

// matchesRecord reports whether an existing record satisfies the input.
// Empty Type, TTL or Data fields in the input act as wildcards, per the
// libdns deletion contract.
func matchesRecord(input, existing libdns.RR) bool {
	if normalizeTarget(input.Name) != normalizeTarget(existing.Name) {
		return false
	}
	if input.Type != "" && !strings.EqualFold(input.Type, existing.Type) {
		return false
	}
	if input.TTL != 0 && input.TTL != existing.TTL {
		return false
	}
	if input.Data != "" && !dataEquals(input.Type, input.Data, existing.Data) {
		return false
	}
	return true
}

// dataEquals compares two rdata strings using rules appropriate to the type.
func dataEquals(recType, a, b string) bool {
	switch strings.ToUpper(recType) {
	case "TXT":
		return unquoteTXT(a) == unquoteTXT(b)
	case "CNAME", "NS", "MX", "SRV", "PTR":
		return normalizeTarget(a) == normalizeTarget(b)
	default:
		return a == b
	}
}

// resolveZone returns an authenticated client and the zone's Bluecat ID.
func (p *Provider) resolveZone(ctx context.Context, zone string) (*Client, int64, error) {
	client, err := p.getClient()
	if err != nil {
		return nil, 0, err
	}

	zoneID, err := client.GetZoneID(ctx, zone, p.ConfigurationName, p.ViewName)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get zone ID: %w", err)
	}

	return client, zoneID, nil
}

// getClient returns the shared client, constructing it on first use.
// Authentication happens lazily inside the client, so this does no I/O.
func (p *Provider) getClient() (*Client, error) {
	p.clientMu.Lock()
	defer p.clientMu.Unlock()

	if p.client != nil {
		return p.client, nil
	}

	if p.ServerURL == "" {
		return nil, errors.New("bluecat: server URL is required")
	}
	if p.Username == "" {
		return nil, errors.New("bluecat: username is required")
	}
	if p.Password == "" {
		return nil, errors.New("bluecat: password is required")
	}

	client, err := NewClient(p.ServerURL, p.Username, p.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	p.client = client
	return client, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
