package bluecat

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDeployZoneCoalescesConcurrentRequests(t *testing.T) {
	var deployCalls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/v2/zones/123/deployments" {
			atomic.AddInt32(&deployCalls, 1)
			w.WriteHeader(http.StatusCreated)
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := &Client{
		baseURL:              server.URL,
		httpClient:           server.Client(),
		authHeader:           "test",
		deployCoalesceWindow: 20 * time.Millisecond,
	}

	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup

	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- client.DeployZone(context.Background(), 123)
		}()
	}

	close(start)
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("DeployZone returned error: %v", err)
		}
	}

	if got := atomic.LoadInt32(&deployCalls); got != 1 {
		t.Fatalf("expected 1 deployment request, got %d", got)
	}
}

func TestDeployZoneStartsNewBatchAfterQuietPeriod(t *testing.T) {
	var deployCalls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/v2/zones/123/deployments" {
			atomic.AddInt32(&deployCalls, 1)
			w.WriteHeader(http.StatusCreated)
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := &Client{
		baseURL:              server.URL,
		httpClient:           server.Client(),
		authHeader:           "test",
		deployCoalesceWindow: 20 * time.Millisecond,
	}

	if err := client.DeployZone(context.Background(), 123); err != nil {
		t.Fatalf("first DeployZone returned error: %v", err)
	}

	time.Sleep(3 * client.deployCoalesceWindow)

	if err := client.DeployZone(context.Background(), 123); err != nil {
		t.Fatalf("second DeployZone returned error: %v", err)
	}

	if got := atomic.LoadInt32(&deployCalls); got != 2 {
		t.Fatalf("expected 2 deployment requests, got %d", got)
	}
}

func TestNewClientUsesDefaultDeployWindow(t *testing.T) {
	client, err := NewClient("https://bluecat.example.com/", "user", "pass", 0)
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}

	if client.deployCoalesceWindow != defaultDeployCoalesceWindow {
		t.Fatalf("expected default deploy window %v, got %v", defaultDeployCoalesceWindow, client.deployCoalesceWindow)
	}
}

func TestNewClientUsesConfiguredDeployWindow(t *testing.T) {
	want := 5 * time.Second
	client, err := NewClient("https://bluecat.example.com/", "user", "pass", want)
	if err != nil {
		t.Fatalf("NewClient returned error: %v", err)
	}

	if client.deployCoalesceWindow != want {
		t.Fatalf("expected deploy window %v, got %v", want, client.deployCoalesceWindow)
	}
}
