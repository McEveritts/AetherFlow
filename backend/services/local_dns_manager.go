package services

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
)

var hostsFileMu sync.Mutex

const (
	defaultHostsFile = "/etc/hosts"
	blockStart       = "# --- AETHERFLOW INTERNAL DNS ---"
	blockEnd         = "# --- END AETHERFLOW INTERNAL DNS ---"
	routeTarget      = "127.0.0.1" // Target for dual-routing loops
)

func resolveHostsFilePath() string {
	if custom := strings.TrimSpace(os.Getenv("AETHERFLOW_HOSTS_FILE")); custom != "" {
		return filepath.Clean(custom)
	}
	return defaultHostsFile
}

// DNSManager handles idempotent injections into /etc/hosts to support
// zero-dependency dual routing natively on debian bare-metal.
type DNSManager struct{}

func NewDNSManager() *DNSManager {
	return &DNSManager{}
}

// AppendOrUpdateDomains updates the internal DNS block in /etc/hosts
// atomically to include the provided .aether.local domains.
// When the privileged runner daemon is available, requests are routed through the socket.
func (d *DNSManager) AppendOrUpdateDomains(domains []string) error {
	if IsRunnerAvailable() {
		return DispatchHostsUpdate(domains)
	}
	return d.AppendOrUpdateDomainsLocal(domains)
}

// RemoveDomains removes the specified .aether.local domains from the managed block in /etc/hosts.
func (d *DNSManager) RemoveDomains(domains []string) error {
	if IsRunnerAvailable() {
		return DispatchHostsRemove(domains)
	}
	return d.RemoveDomainsLocal(domains)
}

func withHostsFileLock(targetHostsFile string, fn func() error) error {
	hostsFileMu.Lock()
	defer hostsFileMu.Unlock()

	lockPath := targetHostsFile + ".af.lock"
	if filepath.Clean(targetHostsFile) == "/etc/hosts" {
		if info, err := os.Stat("/run/aetherflow"); err == nil && info.IsDir() {
			if f, openErr := os.OpenFile("/run/aetherflow/hosts.lock", os.O_CREATE|os.O_RDWR, 0600); openErr == nil {
				_ = f.Close()
				lockPath = "/run/aetherflow/hosts.lock"
			}
		}
	}
	if err := os.MkdirAll(filepath.Dir(lockPath), 0750); err != nil {
		return fmt.Errorf("failed to create lock directory for %s: %w", targetHostsFile, err)
	}
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600) // #nosec G703 -- trusted operator hosts file override
	if err != nil {
		return fmt.Errorf("failed to open hosts lock %s: %w", lockPath, err)
	}
	defer lockFile.Close()

	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("failed to lock %s: %w", lockPath, err)
	}
	defer func() {
		_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
	}()

	return fn()
}

func parseHostsFileContent(content []byte) (outsideLines []string, existingDomains []string, err error) {
	var insideBlock bool
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	for scanner.Scan() {
		line := scanner.Text()
		trimmedLine := strings.TrimSpace(line)

		if trimmedLine == blockStart {
			insideBlock = true
			continue
		}
		if trimmedLine == blockEnd {
			insideBlock = false
			continue
		}

		if insideBlock {
			parts := strings.Fields(trimmedLine)
			if len(parts) >= 2 && parts[0] == routeTarget {
				existingDomains = append(existingDomains, parts[1:]...)
			}
		} else {
			outsideLines = append(outsideLines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	return outsideLines, existingDomains, nil
}

func writeHostsFileAtomically(targetHostsFile, finalContent string) error {
	tmpFile, err := os.CreateTemp(filepath.Dir(targetHostsFile), ".hosts.af-*") // #nosec G703 -- trusted operator hosts file override
	if err != nil {
		return fmt.Errorf("failed to create temporary host file: %w", err)
	}
	tmpHosts := tmpFile.Name()
	cleanupTmp := func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpHosts)
	}

	if _, err := tmpFile.WriteString(finalContent); err != nil {
		cleanupTmp()
		return fmt.Errorf("failed to write temporary host file: %w", err)
	}
	if err := tmpFile.Chmod(0644); err != nil {
		cleanupTmp()
		return fmt.Errorf("failed to set permissions on temporary host file: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		cleanupTmp()
		return fmt.Errorf("failed to sync temporary host file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpHosts)
		return fmt.Errorf("failed to close temporary host file: %w", err)
	}
	if err := os.Rename(tmpHosts, targetHostsFile); err != nil { // #nosec G703 -- trusted operator hosts file override
		_ = os.Remove(tmpHosts)
		return fmt.Errorf("atomic rename on %s failed: %w", targetHostsFile, err)
	}
	return nil
}

// AppendOrUpdateDomainsLocal performs the atomic update directly against the local /etc/hosts.
func (d *DNSManager) AppendOrUpdateDomainsLocal(domains []string) error {
	targetHostsFile := resolveHostsFilePath()

	// Deduplicate domains and build entries map
	entries := make(map[string]bool)
	for _, domain := range domains {
		if !strings.HasSuffix(domain, ".aether.local") {
			return fmt.Errorf("domain %s is not a valid internal aether.local domain", domain)
		}
		entries[domain] = true
	}

	return withHostsFileLock(targetHostsFile, func() error {
		content, err := os.ReadFile(targetHostsFile) // #nosec G703 -- trusted operator hosts file override
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to read %s: %w", targetHostsFile, err)
		}

		outsideLines, existingDomains, err := parseHostsFileContent(content)
		if err != nil {
			return fmt.Errorf("failed to scan %s: %w", targetHostsFile, err)
		}

		for _, ed := range existingDomains {
			entries[ed] = true
		}

		sortedDomains := make([]string, 0, len(entries))
		for domain := range entries {
			sortedDomains = append(sortedDomains, domain)
		}
		sort.Strings(sortedDomains)

		managedBlock := []string{blockStart}
		for _, domain := range sortedDomains {
			managedBlock = append(managedBlock, fmt.Sprintf("%s\t%s", routeTarget, domain))
		}
		managedBlock = append(managedBlock, blockEnd)

		finalLines := append(outsideLines, "")
		finalLines = append(finalLines, managedBlock...)
		finalContent := strings.Join(finalLines, "\n") + "\n"

		return writeHostsFileAtomically(targetHostsFile, finalContent)
	})
}

// RemoveDomainsLocal removes specified .aether.local domains from the managed block in /etc/hosts.
func (d *DNSManager) RemoveDomainsLocal(domains []string) error {
	targetHostsFile := resolveHostsFilePath()

	toRemove := make(map[string]bool)
	for _, domain := range domains {
		if !strings.HasSuffix(domain, ".aether.local") {
			return fmt.Errorf("domain %s is not a valid internal aether.local domain", domain)
		}
		toRemove[domain] = true
	}

	return withHostsFileLock(targetHostsFile, func() error {
		content, err := os.ReadFile(targetHostsFile) // #nosec G703 -- trusted operator hosts file override
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return fmt.Errorf("failed to read %s: %w", targetHostsFile, err)
		}

		outsideLines, existingDomains, err := parseHostsFileContent(content)
		if err != nil {
			return fmt.Errorf("failed to scan %s: %w", targetHostsFile, err)
		}

		entries := make(map[string]bool)
		for _, ed := range existingDomains {
			if !toRemove[ed] {
				entries[ed] = true
			}
		}

		finalLines := outsideLines
		if len(entries) > 0 {
			sortedDomains := make([]string, 0, len(entries))
			for domain := range entries {
				sortedDomains = append(sortedDomains, domain)
			}
			sort.Strings(sortedDomains)

			managedBlock := []string{blockStart}
			for _, domain := range sortedDomains {
				managedBlock = append(managedBlock, fmt.Sprintf("%s\t%s", routeTarget, domain))
			}
			managedBlock = append(managedBlock, blockEnd)
			finalLines = append(finalLines, "")
			finalLines = append(finalLines, managedBlock...)
		}

		finalContent := strings.Join(finalLines, "\n") + "\n"
		return writeHostsFileAtomically(targetHostsFile, finalContent)
	})
}

// ValidateResolution verifies if parsing changes propagated to the OS
// resolver cache before returning true. Essential safety check before
// dropping services to attempt cutovers.
func (d *DNSManager) ValidateResolution(domain string) bool {
	ips, err := net.LookupIP(domain)
	if err != nil {
		return false
	}
	for _, ip := range ips {
		if ip.String() == routeTarget {
			return true
		}
	}
	return false
}
