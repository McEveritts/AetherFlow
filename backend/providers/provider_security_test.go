package providers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestSecurity_ValidateProviderEndpointAndRedirectBlocking(t *testing.T) {
	for _, blocked := range []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://168.63.129.16/machine",
		"http://100.100.100.200/latest/meta-data/",
		"http://[64:ff9b::a9fe:a9fe]/v1",
		"http://[2002:a9fe:a9fe::1]/v1",
		"http://metadata.google.internal/computeMetadata/v1",
		"ftp://api.openai.com/v1",
	} {
		if _, err := ValidateProviderEndpointURL(blocked); err == nil {
			t.Fatalf("expected ValidateProviderEndpointURL to block %s", blocked)
		}
	}

	if got, err := ValidateProviderEndpointURL("http://127.0.0.1:11434/"); err != nil || got != "http://127.0.0.1:11434" {
		t.Fatalf("expected local Ollama loopback endpoint to pass, got=%q err=%v", got, err)
	}
	if got, err := ValidateProviderEndpointURL("https://93.184.216.34/v1/"); err != nil || got != "https://93.184.216.34/v1" {
		t.Fatalf("expected public IPv4 endpoint to pass, got=%q err=%v", got, err)
	}

	var leakedRedirectHits atomic.Int32
	metadataTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leakedRedirectHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer metadataTarget.Close()

	redirectSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, metadataTarget.URL+"/steal", http.StatusFound)
	}))
	defer redirectSrv.Close()

	p, err := NewAnthropicProvider(ProviderConfig{
		APIKey:    "unit-test-provider-token",
		Endpoint:  redirectSrv.URL,
		Transport: redirectSrv.Client().Transport,
	})
	if err != nil {
		t.Fatalf("NewAnthropicProvider failed: %v", err)
	}
	_, chatErr := p.Generate(context.Background(), "hello")
	if chatErr == nil {
		t.Fatalf("expected redirect response to fail rather than follow 302")
	}
	if leakedRedirectHits.Load() != 0 {
		t.Fatalf("expected 0 hits on redirect target, got %d", leakedRedirectHits.Load())
	}

	rawBodySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("<html>SENSITIVE_INTERNAL_TRACE_PAYLOAD</html>"))
	}))
	defer rawBodySrv.Close()

	p2, err := NewAnthropicProvider(ProviderConfig{
		APIKey:    "unit-test-provider-token",
		Endpoint:  rawBodySrv.URL,
		Transport: rawBodySrv.Client().Transport,
	})
	if err != nil {
		t.Fatalf("NewAnthropicProvider p2 failed: %v", err)
	}
	_, bodyErr := p2.Generate(context.Background(), "hello")
	if bodyErr == nil || strings.Contains(bodyErr.Error(), "SENSITIVE_INTERNAL_TRACE_PAYLOAD") {
		t.Fatalf("expected non-reflective error message, got %v", bodyErr)
	}
}
