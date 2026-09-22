package bluecat

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/libdns/libdns"
)

// BluecatResourceRecord represents a resource record in the Bluecat API.
type BluecatResourceRecord struct {
	ID               int64  `json:"id,omitempty"`
	Type             string `json:"type"`
	Name             string `json:"name"`
	AbsoluteName     string `json:"absoluteName,omitempty"`
	TTL              int    `json:"ttl,omitempty"`
	RecordType       string `json:"recordType,omitempty"`
	RData            string `json:"rdata,omitempty"`
	Text             string `json:"text,omitempty"`
	LinkedRecordName string `json:"linkedRecordName,omitempty"`
	Priority         int    `json:"priority,omitempty"`
	Weight           int    `json:"weight,omitempty"`
	Port             int    `json:"port,omitempty"`
	Addresses        []struct {
		Address string `json:"address"`
	} `json:"addresses,omitempty"`
}

// GetResourceRecords retrieves every resource record in a zone, following
// pagination to the end of the collection.
func (c *Client) GetResourceRecords(ctx context.Context, zoneID int64, zone string) ([]libdns.Record, error) {
	path := fmt.Sprintf("/api/v2/zones/%d/resourceRecords", zoneID)

	bcRecords, err := listAll[BluecatResourceRecord](ctx, c, path, nil)
	if err != nil {
		return nil, fmt.Errorf("list resource records for zone %d: %w", zoneID, err)
	}

	records := make([]libdns.Record, 0, len(bcRecords))
	for _, bcRec := range bcRecords {
		rec, err := convertBluecatToLibdns(bcRec, zone)
		if err != nil {
			// Record types libdns has no representation for are skipped
			// rather than surfaced as a generic RR.
			continue
		}
		records = append(records, rec)
	}

	return records, nil
}

// FindResourceRecords returns every record in a zone matching a relative name
// and, when recordType is non-empty, that record type. Fully paginated, and
// returns all matches rather than just the first — an RRset with several
// values (notably concurrent _acme-challenge TXT records) has more than one.
func (c *Client) FindResourceRecords(ctx context.Context, zoneID int64, name, recordType, zone string) ([]BluecatResourceRecord, error) {
	relativeName := normalizeRecordName(name, zone)
	if relativeName == "@" {
		relativeName = ""
	}

	// The resourceRecords endpoint only filters on the zone-relative name;
	// absoluteName and view.name are rejected with InvalidFilterField. Scoping
	// the request to the zone's own collection gives us the view scoping.
	clauses := []string{fmt.Sprintf("name:eq('%s')", escapeFilterValue(relativeName))}
	if recordType != "" {
		clauses = append(clauses, fmt.Sprintf("recordType:eq('%s')", escapeFilterValue(recordType)))
	}

	query := url.Values{}
	query.Set("filter", strings.Join(clauses, " and "))

	path := fmt.Sprintf("/api/v2/zones/%d/resourceRecords", zoneID)
	records, err := listAll[BluecatResourceRecord](ctx, c, path, query)
	if err != nil {
		return nil, fmt.Errorf("find %q (%s) in zone %d: %w", relativeName, recordType, zoneID, err)
	}

	return records, nil
}

// CreateResourceRecord creates a resource record. A duplicate returns an
// *APIError for which IsAlreadyExists reports true; callers that want
// idempotent behaviour should use CreateOrAdopt.
func (c *Client) CreateResourceRecord(ctx context.Context, zoneID int64, zone string, record libdns.Record) (libdns.Record, error) {
	bcRecord, err := convertLibdnsToBluecat(record, zone)
	if err != nil {
		return nil, fmt.Errorf("convert record: %w", err)
	}

	// A replayed POST is exactly how a duplicate gets created, so this
	// request is never retried automatically.
	policy := unsafeRetry()

	var created BluecatResourceRecord
	err = c.do(ctx, apiRequest{
		Method: http.MethodPost,
		Path:   fmt.Sprintf("/api/v2/zones/%d/resourceRecords", zoneID),
		Body:   bcRecord,
		Out:    &created,
		OK:     []int{http.StatusCreated, http.StatusOK},
		Retry:  &policy,
	})
	if err != nil {
		return nil, err
	}

	return convertBluecatToLibdns(created, zone)
}

// CreateOrAdopt creates a record, tolerating the case where it already exists.
//
// Bluecat rejects a duplicate with 409 ResourceAlreadyExists. That happens
// routinely during ACME: a challenge that failed after the record was written
// is retried with the same key authorization, and another cluster node may
// have written the identical record already. In both cases the desired state
// already holds, so re-reading the RRset and adopting a record with a matching
// value is correct and lets issuance proceed.
//
// A conflicting record with a *different* value is not adopted: that would
// silently change data the caller did not ask to change.
func (c *Client) CreateOrAdopt(ctx context.Context, zoneID int64, zone string, record libdns.Record) (libdns.Record, bool, error) {
	created, err := c.CreateResourceRecord(ctx, zoneID, zone, record)
	if err == nil {
		return created, false, nil
	}
	if !IsAlreadyExists(err) {
		return nil, false, err
	}

	rr := record.RR()
	existing, findErr := c.FindResourceRecords(ctx, zoneID, rr.Name, rr.Type, zone)
	if findErr != nil {
		return nil, false, fmt.Errorf("reconcile %w: %v", err, findErr)
	}

	for _, candidate := range existing {
		if !recordValueEquals(record, candidate, zone) {
			continue
		}
		adopted, convErr := convertBluecatToLibdns(candidate, zone)
		if convErr != nil {
			return nil, false, fmt.Errorf("reconcile %w: convert existing record %d: %v", err, candidate.ID, convErr)
		}
		return adopted, true, nil
	}

	if len(existing) == 0 {
		// Bluecat says it's a duplicate but the zone-scoped lookup can't see
		// it. That usually means the record lives somewhere the lookup isn't
		// reaching — a child zone object, or a different view — and it will
		// keep failing until that's resolved, so say so plainly.
		return nil, false, fmt.Errorf(
			"bluecat reported %q for %s %s in zone %d, but no record with that name is visible in the zone; "+
				"it may belong to a child zone or another view: %w",
			codeResourceAlreadyExists, rr.Type, rr.Name, zoneID, err)
	}

	return nil, false, fmt.Errorf(
		"%s %s already exists in zone %d with a different value (%d record(s) present): %w",
		rr.Type, rr.Name, zoneID, len(existing), err)
}

// DeleteResourceRecordByID deletes a resource record. A record that is already
// gone is not an error: the requested end state holds either way.
func (c *Client) DeleteResourceRecordByID(ctx context.Context, recordID int64) error {
	if recordID == 0 {
		return fmt.Errorf("bluecat: record ID cannot be zero")
	}

	err := c.do(ctx, apiRequest{
		Method: http.MethodDelete,
		Path:   fmt.Sprintf("/api/v2/resourceRecords/%d", recordID),
		OK:     []int{http.StatusNoContent, http.StatusOK, http.StatusAccepted},
	})
	if err != nil && !IsNotFound(err) {
		return fmt.Errorf("delete record %d: %w", recordID, err)
	}

	return nil
}

// normalizeRecordName returns a zone-relative libdns name. It accepts either a
// relative name ("_acme-challenge") or an absolute one
// ("_acme-challenge.example.com.").
func normalizeRecordName(name, zone string) string {
	zone = strings.TrimSuffix(zone, ".")
	name = strings.TrimSuffix(name, ".")

	if name == "" || name == "@" || strings.EqualFold(name, zone) {
		return "@"
	}

	if strings.HasSuffix(strings.ToLower(name), "."+strings.ToLower(zone)) {
		return name[:len(name)-len(zone)-1]
	}

	return name
}

// absoluteName joins a zone-relative name to its zone.
func absoluteName(relativeName, zone string) string {
	zone = strings.TrimSuffix(zone, ".")
	if relativeName == "@" || relativeName == "" {
		return zone
	}
	return relativeName + "." + zone
}

// unquoteTXT normalizes a TXT value for comparison. Bluecat may return the
// value with the surrounding quotes and escaping from its wire form, while
// libdns carries the decoded string.
func unquoteTXT(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && strings.HasPrefix(s, `"`) && strings.HasSuffix(s, `"`) {
		s = s[1 : len(s)-1]
	}
	s = strings.ReplaceAll(s, `\"`, `"`)
	s = strings.ReplaceAll(s, `\\`, `\`)
	return s
}

// normalizeTarget normalizes a hostname-valued rdata field for comparison.
func normalizeTarget(s string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
}

// recordValueEquals reports whether a Bluecat record holds the same value as
// the libdns record, ignoring name and TTL. Both the create-adoption path and
// the delete-matching path depend on this, so the normalization rules live
// here and nowhere else.
func recordValueEquals(want libdns.Record, got BluecatResourceRecord, zone string) bool {
	switch rec := want.(type) {
	case libdns.TXT:
		text := got.Text
		if text == "" {
			text = got.RData
		}
		return unquoteTXT(text) == unquoteTXT(rec.Text)

	case libdns.Address:
		return addressMatches(rec.IP, got)

	case libdns.CNAME:
		return normalizeTarget(bluecatTarget(got)) == normalizeTarget(rec.Target)

	case libdns.NS:
		return normalizeTarget(bluecatTarget(got)) == normalizeTarget(rec.Target)

	case libdns.MX:
		return got.Priority == int(rec.Preference) &&
			normalizeTarget(bluecatTarget(got)) == normalizeTarget(rec.Target)

	case libdns.SRV:
		return got.Priority == int(rec.Priority) &&
			got.Weight == int(rec.Weight) &&
			got.Port == int(rec.Port) &&
			normalizeTarget(bluecatTarget(got)) == normalizeTarget(rec.Target)

	case libdns.RR:
		// A generic RR carries its value as text. Compare against whichever
		// field Bluecat populated for this record type.
		return genericValueEquals(rec, got, zone)
	}

	return false
}

func bluecatTarget(got BluecatResourceRecord) string {
	if got.LinkedRecordName != "" {
		return got.LinkedRecordName
	}
	return got.RData
}

func addressMatches(ip netip.Addr, got BluecatResourceRecord) bool {
	for _, a := range got.Addresses {
		if parsed, err := netip.ParseAddr(a.Address); err == nil && parsed == ip {
			return true
		}
	}
	if got.RData != "" {
		if parsed, err := netip.ParseAddr(got.RData); err == nil && parsed == ip {
			return true
		}
	}
	return false
}

// genericValueEquals compares a type-erased libdns.RR against a Bluecat record
// by converting the Bluecat record to its concrete libdns type first, so an RR
// carrying a TXT value is compared with TXT rules.
func genericValueEquals(rr libdns.RR, got BluecatResourceRecord, zone string) bool {
	converted, err := convertBluecatToLibdns(got, zone)
	if err != nil {
		return false
	}
	if concrete, convErr := rr.Parse(); convErr == nil {
		return recordValueEquals(concrete, got, zone)
	}
	return strings.EqualFold(converted.RR().Data, rr.Data)
}

// convertBluecatToLibdns converts a Bluecat resource record to a libdns record.
func convertBluecatToLibdns(bcRec BluecatResourceRecord, zone string) (libdns.Record, error) {
	zone = strings.TrimSuffix(zone, ".")

	name := bcRec.Name
	if bcRec.AbsoluteName != "" {
		name = normalizeRecordName(bcRec.AbsoluteName, zone)
	}
	if name == "" {
		name = "@"
	}

	ttl := time.Duration(bcRec.TTL) * time.Second

	switch bcRec.RecordType {
	case "A", "AAAA":
		var ipStr string
		if len(bcRec.Addresses) > 0 {
			ipStr = bcRec.Addresses[0].Address
		} else if bcRec.RData != "" {
			ipStr = bcRec.RData
		} else {
			return nil, fmt.Errorf("no IP address in record %d", bcRec.ID)
		}
		addr, err := netip.ParseAddr(ipStr)
		if err != nil {
			return nil, fmt.Errorf("parse IP address %q: %w", ipStr, err)
		}
		return libdns.Address{Name: name, TTL: ttl, IP: addr, ProviderData: bcRec.ID}, nil

	case "CNAME":
		return libdns.CNAME{Name: name, TTL: ttl, Target: bluecatTarget(bcRec), ProviderData: bcRec.ID}, nil

	case "TXT":
		text := bcRec.Text
		if text == "" {
			text = bcRec.RData
		}
		return libdns.TXT{Name: name, TTL: ttl, Text: unquoteTXT(text), ProviderData: bcRec.ID}, nil

	case "MX":
		return libdns.MX{
			Name: name, TTL: ttl,
			Preference:   uint16(bcRec.Priority),
			Target:       bluecatTarget(bcRec),
			ProviderData: bcRec.ID,
		}, nil

	case "NS":
		return libdns.NS{Name: name, TTL: ttl, Target: bluecatTarget(bcRec), ProviderData: bcRec.ID}, nil

	case "SRV":
		// SRV names are _service._proto.name; libdns splits these out.
		parts := strings.SplitN(name, ".", 3)
		if len(parts) < 2 {
			return nil, fmt.Errorf("SRV record %d has malformed name %q", bcRec.ID, name)
		}
		recordName := "@"
		if len(parts) == 3 {
			recordName = parts[2]
		}
		return libdns.SRV{
			Service:      strings.TrimPrefix(parts[0], "_"),
			Transport:    strings.TrimPrefix(parts[1], "_"),
			Name:         recordName,
			TTL:          ttl,
			Priority:     uint16(bcRec.Priority),
			Weight:       uint16(bcRec.Weight),
			Port:         uint16(bcRec.Port),
			Target:       bluecatTarget(bcRec),
			ProviderData: bcRec.ID,
		}, nil

	default:
		return nil, fmt.Errorf("unsupported record type %q", bcRec.RecordType)
	}
}

// convertLibdnsToBluecat converts a libdns record to its Bluecat representation.
func convertLibdnsToBluecat(record libdns.Record, zone string) (BluecatResourceRecord, error) {
	// A type-erased RR must be resolved to its concrete type first, or a TXT
	// arriving as an RR would be written as a GenericRecord with rdata rather
	// than a TXTRecord with text — a different object in Bluecat, and one the
	// TXT lookup path would not find.
	if rr, ok := record.(libdns.RR); ok {
		concrete, err := rr.Parse()
		if err != nil {
			return BluecatResourceRecord{}, fmt.Errorf("parse %s record %q: %w", rr.Type, rr.Name, err)
		}
		record = concrete
	}

	rr := record.RR()
	zone = strings.TrimSuffix(zone, ".")
	relativeName := normalizeRecordName(rr.Name, zone)

	bcRec := BluecatResourceRecord{
		Name:         relativeName,
		AbsoluteName: absoluteName(relativeName, zone),
		TTL:          int(rr.TTL.Seconds()),
	}
	if relativeName == "@" {
		bcRec.Name = ""
	}

	switch rec := record.(type) {
	case libdns.Address:
		bcRec.Type = "HostRecord"
		if rec.IP.Is4() {
			bcRec.RecordType = "A"
		} else {
			bcRec.RecordType = "AAAA"
		}
		bcRec.Addresses = []struct {
			Address string `json:"address"`
		}{{Address: rec.IP.String()}}

	case libdns.CNAME:
		bcRec.Type = "AliasRecord"
		bcRec.RecordType = "CNAME"
		bcRec.LinkedRecordName = rec.Target

	case libdns.TXT:
		bcRec.Type = "TXTRecord"
		bcRec.RecordType = "TXT"
		bcRec.Text = rec.Text

	case libdns.MX:
		bcRec.Type = "MXRecord"
		bcRec.RecordType = "MX"
		bcRec.Priority = int(rec.Preference)
		bcRec.LinkedRecordName = rec.Target

	case libdns.NS:
		bcRec.Type = "GenericRecord"
		bcRec.RecordType = "NS"
		bcRec.LinkedRecordName = rec.Target

	case libdns.SRV:
		bcRec.Type = "SRVRecord"
		bcRec.RecordType = "SRV"
		base := normalizeRecordName(rec.Name, zone)
		srvName := fmt.Sprintf("_%s._%s", rec.Service, rec.Transport)
		if base != "@" {
			srvName += "." + base
		}
		bcRec.Name = srvName
		bcRec.AbsoluteName = absoluteName(srvName, zone)
		bcRec.Priority = int(rec.Priority)
		bcRec.Weight = int(rec.Weight)
		bcRec.Port = int(rec.Port)
		bcRec.LinkedRecordName = rec.Target

	default:
		return BluecatResourceRecord{}, fmt.Errorf("unsupported record type %q for %q", rr.Type, rr.Name)
	}

	return bcRec, nil
}
