package services

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestDNSManagerConcurrentAppendAndRemoveUnderFlock(t *testing.T) {
	tmpDir := t.TempDir()
	hostsFile := filepath.Join(tmpDir, "hosts")
	if err := os.WriteFile(hostsFile, []byte("127.0.0.1 localhost\n"), 0644); err != nil {
		t.Fatalf("seed hosts file: %v", err)
	}
	t.Setenv("AETHERFLOW_HOSTS_FILE", hostsFile)

	mgr := NewDNSManager()
	const workers = 8
	var wg sync.WaitGroup
	errs := make(chan error, workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if err := mgr.AppendOrUpdateDomainsLocal([]string{fmt.Sprintf("app%d.aether.local", idx)}); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent append failed: %v", err)
	}

	raw, err := os.ReadFile(hostsFile)
	if err != nil {
		t.Fatalf("read hosts file: %v", err)
	}
	text := string(raw)
	if !strings.Contains(text, "127.0.0.1 localhost") {
		t.Fatalf("existing hosts entry lost:\n%s", text)
	}
	for i := 0; i < workers; i++ {
		domain := fmt.Sprintf("app%d.aether.local", i)
		if !strings.Contains(text, domain) {
			t.Fatalf("lost concurrent update for %s:\n%s", domain, text)
		}
	}

	// Remove half concurrently
	var rwg sync.WaitGroup
	rerrs := make(chan error, workers/2)
	for i := 0; i < workers/2; i++ {
		rwg.Add(1)
		go func(idx int) {
			defer rwg.Done()
			if err := mgr.RemoveDomainsLocal([]string{fmt.Sprintf("app%d.aether.local", idx)}); err != nil {
				rerrs <- err
			}
		}(i)
	}
	rwg.Wait()
	close(rerrs)
	for err := range rerrs {
		t.Fatalf("concurrent remove failed: %v", err)
	}

	after, err := os.ReadFile(hostsFile)
	if err != nil {
		t.Fatalf("read hosts file after remove: %v", err)
	}
	afterText := string(after)
	for i := 0; i < workers/2; i++ {
		domain := fmt.Sprintf("app%d.aether.local", i)
		if strings.Contains(afterText, domain) {
			t.Fatalf("expected removed domain %s absent:\n%s", domain, afterText)
		}
	}
	for i := workers / 2; i < workers; i++ {
		domain := fmt.Sprintf("app%d.aether.local", i)
		if !strings.Contains(afterText, domain) {
			t.Fatalf("expected remaining domain %s kept:\n%s", domain, afterText)
		}
	}
}
