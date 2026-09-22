package bluecat

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// maxRawBody caps how much of an unparseable error body we retain.
const maxRawBody = 4 << 10

// Bluecat error codes we act on. Bluecat returns these in the "code" field of
// its error envelope; match on these rather than on message text, which is not
// part of any compatibility contract.
const (
	codeResourceAlreadyExists = "ResourceAlreadyExists"
	codeDuplicateItem         = "DuplicateItem"
)

// APIError is a structured error response from the Bluecat v2 API.
//
// Bluecat returns errors as a JSON envelope, e.g.:
//
//	{"status":409,"reason":"Conflict","code":"ResourceAlreadyExists",
//	 "message":"The request attempted to create a resource that already exists",
//	 "detail":"Duplicate of another item"}
//
// Callers should test for specific conditions with IsAlreadyExists, IsNotFound,
// IsAuthError and IsRetryable rather than inspecting fields directly.
type APIError struct {
	StatusCode int    `json:"status"`
	Reason     string `json:"reason"`
	Code       string `json:"code"`
	Message    string `json:"message"`
	Detail     string `json:"detail"`

	// Method and Path identify the request that failed. Not part of the
	// Bluecat envelope; filled in by the transport.
	Method string `json:"-"`
	Path   string `json:"-"`

	// RawBody holds the (truncated) response body when it did not parse as
	// an error envelope. Empty when Code/Message were populated.
	RawBody string `json:"-"`
}

func (e *APIError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "bluecat: %s %s: status %d", e.Method, e.Path, e.StatusCode)
	if e.Code != "" {
		fmt.Fprintf(&b, " (%s)", e.Code)
	}
	switch {
	case e.Message != "" && e.Detail != "":
		fmt.Fprintf(&b, ": %s: %s", e.Message, e.Detail)
	case e.Message != "":
		fmt.Fprintf(&b, ": %s", e.Message)
	case e.RawBody != "":
		fmt.Fprintf(&b, ": %s", e.RawBody)
	}
	return b.String()
}

// parseAPIError builds an APIError from a failed response. body may be empty.
func parseAPIError(method, path string, statusCode int, body []byte) *APIError {
	apiErr := &APIError{StatusCode: statusCode, Method: method, Path: path}

	// Bluecat echoes the status inside the envelope; don't let a malformed or
	// absent one overwrite the real HTTP status.
	if err := json.Unmarshal(body, apiErr); err != nil || apiErr.Code == "" && apiErr.Message == "" {
		apiErr.Code = ""
		apiErr.Message = ""
		apiErr.Detail = ""
		apiErr.Reason = ""
		apiErr.RawBody = truncate(strings.TrimSpace(string(body)), maxRawBody)
	}
	apiErr.StatusCode = statusCode

	return apiErr
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "... (truncated)"
}

// IsAlreadyExists reports whether err is a Bluecat duplicate-resource error,
// i.e. the record we tried to create is already present.
func IsAlreadyExists(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.Code {
	case codeResourceAlreadyExists, codeDuplicateItem:
		return true
	}
	// Fall back to the status when Bluecat reports a code we don't know.
	return apiErr.Code == "" && apiErr.StatusCode == http.StatusConflict
}

// IsNotFound reports whether err indicates the resource does not exist.
// Deletes treat this as success, since the desired end state already holds.
func IsNotFound(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound
}

// IsAuthError reports whether err indicates the session is invalid or expired.
// The transport uses this to trigger re-authentication.
func IsAuthError(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.StatusCode == http.StatusUnauthorized || apiErr.StatusCode == http.StatusForbidden
}

// IsRetryable reports whether err is transient and the request may be retried.
// Transport-level failures qualify; so do 429 and 5xx. Note that retrying is
// only safe for idempotent requests — see retryPolicy.Unsafe.
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		// Not an API-level error, so it's a transport failure. Context
		// cancellation is the caller giving up, not something to retry.
		return !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
	}

	switch apiErr.StatusCode {
	case http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	}
	return false
}
