// Package bluecat implements a DNS record management client compatible
// with the libdns interfaces for Bluecat Address Manager.
package bluecat

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/libdns/libdns"
)

// deployState tracks a pending debounced deployment for a single zone.
type deployState struct {
	timer  *time.Timer
	zoneID int64
}

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
	// Defaults to 10 seconds when zero or unset.
	// Set to -1 to disable automatic deployment entirely (advanced use only).
	DeployDelay time.Duration `json:"deploy_delay,omitempty"`

	client         *Client
	mu             sync.Mutex
	deployMu       sync.Mutex
	pendingDeploys map[int64]*deployState
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	if err := p.ensureClient(ctx); err != nil {
		return nil, err
	}

	// Get the zone ID
	zoneID, err := p.client.GetZoneID(ctx, zone, p.ConfigurationName, p.ViewName)
	if err != nil {
		return nil, fmt.Errorf("failed to get zone ID: %w", err)
	}

	// Get all resource records for the zone
	records, err := p.client.GetResourceRecords(ctx, zoneID, zone)
	if err != nil {
		return nil, fmt.Errorf("failed to get resource records: %w", err)
	}

	return records, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	if err := p.ensureClient(ctx); err != nil {
		return nil, err
	}

	// Get the zone ID
	zoneID, err := p.client.GetZoneID(ctx, zone, p.ConfigurationName, p.ViewName)
	if err != nil {
		return nil, fmt.Errorf("failed to get zone ID: %w", err)
	}

	var created []libdns.Record
	for _, record := range records {
		rec, err := p.client.CreateResourceRecord(ctx, zoneID, zone, record)
		if err != nil {
			return created, fmt.Errorf("failed to create record: %w", err)
		}
		created = append(created, rec)
	}

	p.scheduleDeployZone(zoneID)

	return created, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	if err := p.ensureClient(ctx); err != nil {
		return nil, err
	}

	// Get the zone ID
	zoneID, err := p.client.GetZoneID(ctx, zone, p.ConfigurationName, p.ViewName)
	if err != nil {
		return nil, fmt.Errorf("failed to get zone ID: %w", err)
	}

	// Get existing records to determine what needs to be updated/created/deleted
	existingRecords, err := p.client.GetResourceRecords(ctx, zoneID, zone)
	if err != nil {
		return nil, fmt.Errorf("failed to get existing records: %w", err)
	}

	// Build maps for easier comparison
	recordsByNameType := make(map[string][]libdns.Record)
	for _, rec := range records {
		rr := rec.RR()
		key := rr.Name + ":" + rr.Type
		recordsByNameType[key] = append(recordsByNameType[key], rec)
	}

	existingByNameType := make(map[string][]libdns.Record)
	for _, rec := range existingRecords {
		rr := rec.RR()
		key := rr.Name + ":" + rr.Type
		existingByNameType[key] = append(existingByNameType[key], rec)
	}

	var updated []libdns.Record

	// Delete records that exist in Bluecat but not in our new set
	for key, existingRecs := range existingByNameType {
		if _, exists := recordsByNameType[key]; !exists {
			// Delete all records with this name/type combo
			for _, rec := range existingRecs {
				if err := p.client.DeleteResourceRecord(ctx, rec); err != nil {
					return updated, fmt.Errorf("failed to delete record: %w", err)
				}
			}
		}
	}

	// Create or update records
	for _, rec := range records {
		rr := rec.RR()
		key := rr.Name + ":" + rr.Type

		if existing, exists := existingByNameType[key]; exists {
			// Update existing record - for simplicity, delete old and create new
			for _, oldRec := range existing {
				if err := p.client.DeleteResourceRecord(ctx, oldRec); err != nil {
					return updated, fmt.Errorf("failed to delete old record: %w", err)
				}
			}
		}

		// Create the new record
		created, err := p.client.CreateResourceRecord(ctx, zoneID, zone, rec)
		if err != nil {
			return updated, fmt.Errorf("failed to create/update record: %w", err)
		}
		updated = append(updated, created)
	}

	p.scheduleDeployZone(zoneID)

	return updated, nil
}

// DeleteRecords deletes the specified records from the zone. It returns the records that were deleted.
// If records have BlueCat IDs in ProviderData, those are used directly.
// Otherwise, records are looked up by absoluteName to find their IDs.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	if err := p.ensureClient(ctx); err != nil {
		return nil, err
	}

	// Clean up zone
	zone = strings.TrimSuffix(zone, ".")

	// Get the zone ID for deployment later
	zoneID, err := p.client.GetZoneID(ctx, zone, p.ConfigurationName, p.ViewName)
	if err != nil {
		return nil, fmt.Errorf("failed to get zone ID: %w", err)
	}

	var deleted []libdns.Record

	for _, record := range records {
		rr := record.RR()
		recordID := getRecordID(record)

		// If we do not have a record ID, look it up by absoluteName
		if recordID == 0 {
			// Construct the absolute name
			var absoluteName string
			if rr.Name == "@" || rr.Name == "" {
				absoluteName = zone
			} else {
				absoluteName = rr.Name + "." + zone
			}

			bcRecord, err := p.client.GetResourceRecordByAbsoluteName(ctx, absoluteName, rr.Type)
			if err != nil {
				return deleted, fmt.Errorf("failed to lookup record %s: %w", absoluteName, err)
			}

			if bcRecord == nil {
				// Record not found - it may have been already deleted, continue
				deleted = append(deleted, record)
				continue
			}

			recordID = bcRecord.ID
		}

		if err := p.client.DeleteResourceRecordByID(ctx, recordID); err != nil {
			return deleted, fmt.Errorf("failed to delete record by ID %d: %w", recordID, err)
		}
		deleted = append(deleted, record)
	}

	if len(deleted) > 0 {
		p.scheduleDeployZone(zoneID)
	}

	return deleted, nil
}

// getRecordID extracts the BlueCat record ID from ProviderData
func getRecordID(record libdns.Record) int64 {
	switch rec := record.(type) {
	case libdns.Address:
		if id, ok := rec.ProviderData.(int64); ok {
			return id
		}
	case libdns.CNAME:
		if id, ok := rec.ProviderData.(int64); ok {
			return id
		}
	case libdns.TXT:
		if id, ok := rec.ProviderData.(int64); ok {
			return id
		}
	case libdns.MX:
		if id, ok := rec.ProviderData.(int64); ok {
			return id
		}
	case libdns.NS:
		if id, ok := rec.ProviderData.(int64); ok {
			return id
		}
	case libdns.SRV:
		if id, ok := rec.ProviderData.(int64); ok {
			return id
		}
	}
	return 0
}

// scheduleDeployZone debounces QuickDeploy calls for a given zone.
// It resets the deploy timer on every call; the actual deploy fires
// only after no new calls arrive within DeployDelay.
func (p *Provider) scheduleDeployZone(zoneID int64) {
	if p.DeployDelay == -1 {
		return
	}

	delay := p.DeployDelay
	if delay <= 0 {
		delay = 10 * time.Second
	}

	p.deployMu.Lock()
	defer p.deployMu.Unlock()

	if p.pendingDeploys == nil {
		p.pendingDeploys = make(map[int64]*deployState)
	}

	if state, ok := p.pendingDeploys[zoneID]; ok {
		// Another write arrived — reset the timer to wait longer.
		state.timer.Reset(delay)
		return
	}

	// First write for this zone in this window — arm the timer.
	state := &deployState{zoneID: zoneID}
	state.timer = time.AfterFunc(delay, func() {
		p.deployMu.Lock()
		delete(p.pendingDeploys, zoneID)
		p.deployMu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()

		if err := p.client.DeployZone(ctx, zoneID); err != nil {
			// Deploy errors are logged here; they do not surface to the
			// caller because the deploy is async. Caddy will retry the
			// full ACME flow on the next renewal cycle if DNS propagation
			// fails as a result.
			fmt.Printf("bluecat: deferred deploy for zone %d failed: %v\n", zoneID, err)
		}
	})
	p.pendingDeploys[zoneID] = state
}

// ensureClient ensures the client is initialized and authenticated
func (p *Provider) ensureClient(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.client != nil {
		return nil
	}

	if p.ServerURL == "" {
		return fmt.Errorf("server URL is required")
	}
	if p.Username == "" {
		return fmt.Errorf("username is required")
	}
	if p.Password == "" {
		return fmt.Errorf("password is required")
	}

	client, err := NewClient(p.ServerURL, p.Username, p.Password)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	if err := client.Authenticate(ctx); err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}

	p.client = client
	return nil
}

// matchesRecord checks if two records match based on the provided criteria
// If the input record has empty Type, TTL, or Data, those fields are ignored in the comparison
func matchesRecord(input, existing libdns.RR) bool {
	if input.Name != existing.Name {
		return false
	}
	if input.Type != "" && input.Type != existing.Type {
		return false
	}
	if input.TTL != 0 && input.TTL != existing.TTL {
		return false
	}
	if input.Data != "" && input.Data != existing.Data {
		return false
	}
	return true
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
