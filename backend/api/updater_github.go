package api

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type githubUpdateError struct {
	status  int
	retryAt time.Time
}

func (failure *githubUpdateError) Error() string {
	if !failure.retryAt.IsZero() {
		return "GitHub API rate limit reached; retry after " + failure.retryAt.UTC().Format(time.RFC3339)
	}
	return fmt.Sprintf("GitHub update API returned HTTP %d", failure.status)
}

type githubUpdateEntry struct {
	body    []byte
	err     error
	expires time.Time
}

type githubUpdateCache struct {
	mu      sync.Mutex
	entries map[string]githubUpdateEntry
	token   string
	limited *githubUpdateError
}

var updateGitHubCache githubUpdateCache

func githubUpdateToken() string {
	for _, key := range []string{"AF_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"} {
		if token := strings.TrimSpace(os.Getenv(key)); token != "" {
			return token
		}
	}
	return ""
}

func (cache *githubUpdateCache) fetch(client *http.Client, url, token string, now time.Time) ([]byte, error) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.entries == nil || cache.token != token {
		cache.entries = make(map[string]githubUpdateEntry)
		cache.token = token
		cache.limited = nil
	}
	if entry, found := cache.entries[url]; found && now.Before(entry.expires) {
		return entry.body, entry.err
	}
	if cache.limited != nil && now.Before(cache.limited.retryAt) {
		return nil, cache.limited
	}
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("User-Agent", "AetherFlow-Updater")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := client.Do(request)
	entry := githubUpdateEntry{expires: now.Add(time.Minute), err: err}
	if err == nil {
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			failure := &githubUpdateError{status: response.StatusCode}
			if response.StatusCode == http.StatusTooManyRequests ||
				(response.StatusCode == http.StatusForbidden && (response.Header.Get("X-RateLimit-Remaining") == "0" || response.Header.Get("Retry-After") != "")) {
				failure.retryAt = now.Add(time.Minute)
				if reset, parseErr := strconv.ParseInt(response.Header.Get("X-RateLimit-Reset"), 10, 64); parseErr == nil && time.Unix(reset, 0).After(failure.retryAt) {
					failure.retryAt = time.Unix(reset, 0)
				}
				if seconds, parseErr := strconv.Atoi(response.Header.Get("Retry-After")); parseErr == nil && seconds > 0 {
					if retry := now.Add(time.Duration(seconds) * time.Second); retry.After(failure.retryAt) {
						failure.retryAt = retry
					}
				} else if retry, parseErr := http.ParseTime(response.Header.Get("Retry-After")); parseErr == nil && retry.After(failure.retryAt) {
					failure.retryAt = retry
				}
				entry.expires = failure.retryAt
				cache.limited = failure
			}
			entry.err = failure
		} else {
			entry.body, entry.err = io.ReadAll(io.LimitReader(response.Body, 4<<20))
			if entry.err == nil {
				entry.expires = now.Add(5 * time.Minute)
			}
		}
	}
	cache.entries[url] = entry
	return entry.body, entry.err
}

func fetchGitHubUpdate(path string) ([]byte, error) {
	return updateGitHubCache.fetch(httpClient, "https://api.github.com/repos/"+githubRepo+path, githubUpdateToken(), time.Now())
}
