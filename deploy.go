package bluecat

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// bluecatDeployment is the subset of the Bluecat deployment resource we need.
type bluecatDeployment struct {
	ID     int64  `json:"id"`
	Status string `json:"status"`
}

// Deployment statuses Bluecat reports. Compared case-insensitively, since the
// exact casing has varied across BAM versions.
var (
	deploySucceeded = []string{"COMPLETE", "COMPLETED", "DONE", "SUCCESS", "SUCCEEDED", "FINISHED"}
	deployFailed    = []string{"FAILED", "ERROR", "CANCELLED", "CANCELED", "ABORTED"}
)

// DeployZone triggers a quick deployment of a zone and waits until Bluecat
// confirms it is complete, so callers don't begin DNS propagation checks
// before the records are actually live on the authoritative servers.
func (c *Client) DeployZone(ctx context.Context, zoneID int64) error {
	path := fmt.Sprintf("/api/v2/zones/%d/deployments", zoneID)

	var dep bluecatDeployment
	var status int
	// Deployment is not idempotent in the sense that a replay creates a
	// second deployment, so don't retry it automatically.
	policy := unsafeRetry()
	err := c.do(ctx, apiRequest{
		Method: http.MethodPost,
		Path:   path,
		Body:   map[string]string{"type": "QuickDeployment"},
		Out:    &dep,
		Status: &status,
		OK:     []int{http.StatusCreated, http.StatusOK, http.StatusAccepted},
		Retry:  &policy,
	})
	if err != nil {
		return fmt.Errorf("deploy zone %d: %w", zoneID, err)
	}

	// 200 and 201 mean the deployment already finished. Only 202 means it was
	// queued and still needs to be waited on.
	if status != http.StatusAccepted {
		return nil
	}

	// Without a deployment ID there is nothing to poll. Wait one interval as
	// a best-effort settle rather than returning immediately.
	if dep.ID == 0 {
		return c.sleep(ctx, c.deployPollInterval)
	}

	return c.waitForDeployment(ctx, dep.ID)
}

// waitForDeployment polls a deployment until it reaches a terminal status.
func (c *Client) waitForDeployment(ctx context.Context, deployID int64) error {
	path := fmt.Sprintf("/api/v2/deployments/%d", deployID)

	deadline := time.Now().Add(c.deployPollTimeout)
	lastStatus := "unknown"

	for {
		if err := c.sleep(ctx, c.deployPollInterval); err != nil {
			return err
		}

		var dep bluecatDeployment
		if err := c.do(ctx, apiRequest{
			Method: http.MethodGet,
			Path:   path,
			Out:    &dep,
		}); err != nil {
			// A transient failure mid-deployment shouldn't abort the wait,
			// but a permanent one should.
			if !IsRetryable(err) && !IsNotFound(err) {
				return fmt.Errorf("poll deployment %d: %w", deployID, err)
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("timed out polling deployment %d (last error: %w)", deployID, err)
			}
			continue
		}

		if dep.Status != "" {
			lastStatus = dep.Status
		}

		switch {
		case matchesStatus(dep.Status, deploySucceeded):
			return nil
		case matchesStatus(dep.Status, deployFailed):
			return fmt.Errorf("deployment %d finished with status %s", deployID, dep.Status)
		}

		// QUEUED, RUNNING, and anything we don't recognise: keep polling.
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %s waiting for deployment %d to complete (last status %q)",
				c.deployPollTimeout, deployID, lastStatus)
		}
	}
}

func matchesStatus(status string, want []string) bool {
	for _, w := range want {
		if strings.EqualFold(status, w) {
			return true
		}
	}
	return false
}
