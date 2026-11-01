package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"aetherflow/db"
	"github.com/gin-gonic/gin"
)

func TestGitHubUpdateCachesConcurrentChecks(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.Header.Get("Authorization") != "Bearer test-token" || request.Header.Get("Accept") != "application/vnd.github+json" {
			t.Error("missing GitHub request headers")
		}
		fmt.Fprint(writer, `[{"tag_name":"v3.2.7"}]`)
	}))
	defer server.Close()
	var cache githubUpdateCache
	now := time.Now()
	var workers sync.WaitGroup
	for index := 0; index < 20; index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			body, err := cache.fetch(server.Client(), server.URL, "test-token", now)
			if err != nil || !strings.Contains(string(body), "v3.2.7") {
				t.Errorf("fetch: %s, %v", body, err)
			}
		}()
	}
	workers.Wait()
	if requests.Load() != 1 {
		t.Fatalf("got %d upstream requests, want 1", requests.Load())
	}
	if _, err := cache.fetch(server.Client(), server.URL, "test-token", now.Add(6*time.Minute)); err != nil || requests.Load() != 2 {
		t.Fatalf("cache did not expire: requests=%d error=%v", requests.Load(), err)
	}
}

func TestGitHubUpdateRateLimitBlocksFallbackRequests(t *testing.T) {
	var requests atomic.Int32
	now := time.Now().Truncate(time.Second)
	reset := now.Add(30 * time.Minute)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		writer.Header().Set("X-RateLimit-Remaining", "0")
		writer.Header().Set("X-RateLimit-Reset", strconv.FormatInt(reset.Unix(), 10))
		writer.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	var cache githubUpdateCache
	for _, path := range []string{"/releases", "/releases", "/commits/nightly"} {
		_, err := cache.fetch(server.Client(), server.URL+path, "", now)
		var failure *githubUpdateError
		if !errors.As(err, &failure) || !failure.retryAt.Equal(reset) {
			t.Fatalf("missing reset deadline: %v", err)
		}
	}
	if requests.Load() != 1 {
		t.Fatalf("rate-limited checks made %d requests", requests.Load())
	}
	cache.fetch(server.Client(), server.URL+"/releases", "", reset.Add(time.Second))
	if requests.Load() != 2 {
		t.Fatal("request did not resume after reset")
	}
}

func TestGitHubUpdateRetryAfterAndAuthenticationChange(t *testing.T) {
	for _, retryHeader := range []string{"120", time.Now().Add(2 * time.Minute).UTC().Format(http.TimeFormat)} {
		t.Run(retryHeader, func(t *testing.T) {
			var requests atomic.Int32
			now := time.Now()
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				requests.Add(1)
				if request.Header.Get("Authorization") != "" {
					fmt.Fprint(writer, "[]")
					return
				}
				writer.Header().Set("Retry-After", retryHeader)
				writer.WriteHeader(http.StatusTooManyRequests)
			}))
			defer server.Close()
			var cache githubUpdateCache
			_, err := cache.fetch(server.Client(), server.URL, "", now)
			var failure *githubUpdateError
			if !errors.As(err, &failure) || failure.retryAt.Before(now.Add(90*time.Second)) {
				t.Fatalf("Retry-After not honored: %v", err)
			}
			if _, err := cache.fetch(server.Client(), server.URL, "new-token", now); err != nil || requests.Load() != 2 {
				t.Fatalf("new authentication did not clear backoff: %v", err)
			}
		})
	}
}

func TestGitHubUpdateErrorsAreNotSuccess(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		writer.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	var cache githubUpdateCache
	now := time.Now()
	for index := 0; index < 2; index++ {
		if _, err := cache.fetch(server.Client(), server.URL, "", now); err == nil || !strings.Contains(err.Error(), "403") {
			t.Fatalf("HTTP error was suppressed: %v", err)
		}
	}
	if requests.Load() != 1 {
		t.Fatal("failures were not cached")
	}
}

func TestGitHubUpdateTokenPreference(t *testing.T) {
	t.Setenv("GH_TOKEN", "gh")
	t.Setenv("GITHUB_TOKEN", "github")
	t.Setenv("AF_GITHUB_TOKEN", " dedicated ")
	if githubUpdateToken() != "dedicated" {
		t.Fatal("dedicated token not preferred")
	}
	t.Setenv("AF_GITHUB_TOKEN", "")
	if githubUpdateToken() != "github" {
		t.Fatal("GITHUB_TOKEN fallback not used")
	}
}

func TestGitHubUpdateHandlerReportsRateLimit(t *testing.T) {
	connection, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := connection.Exec("CREATE TABLE settings (id INTEGER PRIMARY KEY, update_channel TEXT); INSERT INTO settings VALUES (1, 'nightly')"); err != nil {
		t.Fatal(err)
	}
	previousDB := db.DB
	db.DB = connection
	t.Cleanup(func() { db.DB = previousDB })
	reset := time.Now().Add(30 * time.Minute).Truncate(time.Second)
	updateGitHubCache.mu.Lock()
	previousEntries, previousToken, previousLimit := updateGitHubCache.entries, updateGitHubCache.token, updateGitHubCache.limited
	updateGitHubCache.entries = make(map[string]githubUpdateEntry)
	updateGitHubCache.token = githubUpdateToken()
	updateGitHubCache.limited = &githubUpdateError{status: http.StatusForbidden, retryAt: reset}
	updateGitHubCache.mu.Unlock()
	t.Cleanup(func() {
		updateGitHubCache.mu.Lock()
		defer updateGitHubCache.mu.Unlock()
		updateGitHubCache.entries, updateGitHubCache.token, updateGitHubCache.limited = previousEntries, previousToken, previousLimit
	})
	router := gin.New()
	router.GET("/check", CheckUpdate)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/check", nil))
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != "github_rate_limited" || body["retryAt"] != reset.UTC().Format(time.RFC3339) {
		t.Fatalf("missing actionable rate-limit response: %s", response.Body.String())
	}
}
