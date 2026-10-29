package services

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	defaultHostsFile = "/etc/hosts"
	blockStart       = "# --- AETHERFLOW INTERNAL DNS ---"
	blockEnd         = "# --- END AETHERFLOW INTERNAL DNS ---"
	routeTarget      = "127.0.0.1" // Target for dual-routing loops
)

func resolveHostsFilePath() string {
	if custom := strings.TrimSpace(os.Getenv("AETHERFLOW_HOSTS_FILE")); custom != "" {
		return custom
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

	content, err := os.ReadFile(targetHostsFile)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to read %s: %w", targetHostsFile, err)
	}

	// Parse current file, preserving content outside our block
	// and harvesting existing AetherFlow entries inside our block
	var newVars []string
	var existingDomains []string
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
			newVars = append(newVars, line)
		}
	}

	for _, ed := range existingDomains {
		entries[ed] = true
	}

	sortedDomains := make([]string, 0, len(entries))
	for domain := range entries {
		sortedDomains = append(sortedDomains, domain)
	}
	sort.Strings(sortedDomains)

	// Rebuild our managed block
	managedBlock := []string{blockStart}
	for _, domain := range sortedDomains {
		managedBlock = append(managedBlock, fmt.Sprintf("%s\t%s", routeTarget, domain))
	}
	managedBlock = append(managedBlock, blockEnd)

	// Combine untouched lines + rebuilt block
	finalLines := append(newVars, "")
	finalLines = append(finalLines, managedBlock...)
	finalContent := strings.Join(finalLines, "\n") + "\n"

	// Atomic write sequence
	tmpHosts := targetHostsFile + fmt.Sprintf(".tmp.%d", time.Now().UnixNano())
	if err := os.WriteFile(tmpHosts, []byte(finalContent), 0644); err != nil {
		return fmt.Errorf("failed to write temporary host file: %w", err)
	}

	if err := os.Rename(tmpHosts, targetHostsFile); err != nil {
		os.Remove(tmpHosts)
		return fmt.Errorf("atomic rename on %s failed: %w", targetHostsFile, err)
	}

	return nil
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

	content, err := os.ReadFile(targetHostsFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read %s: %w", targetHostsFile, err)
	}

	var newVars []string
	entries := make(map[string]bool)
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
				for _, ed := range parts[1:] {
					if !toRemove[ed] {
						entries[ed] = true
					}
				}
			}
		} else {
			newVars = append(newVars, line)
		}
	}

	finalLines := newVars
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
	tmpHosts := targetHostsFile + fmt.Sprintf(".tmp.%d", time.Now().UnixNano())
	if err := os.WriteFile(tmpHosts, []byte(finalContent), 0644); err != nil {
		return fmt.Errorf("failed to write temporary host file: %w", err)
	}
	if err := os.Rename(tmpHosts, targetHostsFile); err != nil {
		os.Remove(tmpHosts)
		return fmt.Errorf("atomic rename on %s failed: %w", targetHostsFile, err)
	}

	return nil
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
