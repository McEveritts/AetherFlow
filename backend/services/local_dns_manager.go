package services

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

const (
	hostsFile   = "/etc/hosts"
	blockStart  = "# --- AETHERFLOW INTERNAL DNS ---"
	blockEnd    = "# --- END AETHERFLOW INTERNAL DNS ---"
	routeTarget = "127.0.0.1" // Target for dual-routing loops
)

// DNSManager handles idempotent injections into /etc/hosts to support
// zero-dependency dual routing natively on debian bare-metal.
type DNSManager struct{}

func NewDNSManager() *DNSManager {
	return &DNSManager{}
}

// AppendOrUpdateDomains updates the internal DNS block in /etc/hosts 
// atomically to include the provided .aether.local domains.
func (d *DNSManager) AppendOrUpdateDomains(domains []string) error {
	// Deduplicate domains and build entries map
	entries := make(map[string]bool)
	for _, domain := range domains {
		if !strings.HasSuffix(domain, ".aether.local") {
			return fmt.Errorf("domain %s is not a valid internal aether.local domain", domain)
		}
		entries[domain] = true
	}

	content, err := os.ReadFile(hostsFile)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to read %s: %w", hostsFile, err)
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
			// Extract existing domain if formatted properly (e.g. "127.0.0.1 radarr.aether.local")
			parts := strings.Fields(trimmedLine)
			if len(parts) >= 2 && parts[0] == routeTarget {
				for _, p := range parts[1:] {
					existingDomains = append(existingDomains, p)
				}
			}
		} else {
			newVars = append(newVars, line)
		}
	}

	// Merge existing internal domains into our target entries
	for _, ed := range existingDomains {
		entries[ed] = true
	}

	// Rebuild our managed block
	managedBlock := []string{blockStart}
	for domain := range entries {
		managedBlock = append(managedBlock, fmt.Sprintf("%s\t%s", routeTarget, domain))
	}
	managedBlock = append(managedBlock, blockEnd)

	// Combine untouched lines + rebuilt block
	finalLines := append(newVars, "") // Empty spacer before block
	finalLines = append(finalLines, managedBlock...)
	finalContent := strings.Join(finalLines, "\n") + "\n"

	// Atomic write sequence
	tmpHosts := hostsFile + fmt.Sprintf(".tmp.%d", time.Now().UnixNano())
	if err := os.WriteFile(tmpHosts, []byte(finalContent), 0644); err != nil {
		return fmt.Errorf("failed to write temporary host file: %w", err)
	}

	if err := os.Rename(tmpHosts, hostsFile); err != nil {
		os.Remove(tmpHosts) // attempt cleanup if rename fails
		return fmt.Errorf("atomic rename on /etc/hosts failed: %w", err)
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
