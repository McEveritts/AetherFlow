package services

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// XMLMutator manages XML configuration files used by *arr applications (config.xml)
// and Jellyfin (network.xml), preserving unrelated elements while applying blueprint settings.
type XMLMutator struct {
	ConfigPath string
	RootTag    string // "Config" or "NetworkConfiguration"
}

func NewXMLMutator(path string, rootTag string) *XMLMutator {
	if rootTag == "" {
		if strings.Contains(strings.ToLower(path), "jellyfin") || strings.HasSuffix(strings.ToLower(path), "network.xml") {
			rootTag = "NetworkConfiguration"
		} else {
			rootTag = "Config"
		}
	}
	return &XMLMutator{
		ConfigPath: path,
		RootTag:    rootTag,
	}
}

func (xm *XMLMutator) Backup() error {
	if _, err := os.Stat(xm.ConfigPath); os.IsNotExist(err) {
		return nil
	}
	return copyFileStruct(xm.ConfigPath, xm.ConfigPath+".bak")
}

func (xm *XMLMutator) Restore() error {
	if _, err := os.Stat(xm.ConfigPath + ".bak"); os.IsNotExist(err) {
		return nil
	}
	return copyFileStruct(xm.ConfigPath+".bak", xm.ConfigPath)
}

// InjectRoutes updates XML keys or values matching the provided map.
func (xm *XMLMutator) InjectRoutes(routes map[string]string) error {
	return xm.ApplySettings(routes)
}

// ApplySettings writes or updates XML elements inside the configuration file.
func (xm *XMLMutator) ApplySettings(settings map[string]string) error {
	if xm.ConfigPath == "" || len(settings) == 0 {
		return nil
	}

	contentBytes, err := os.ReadFile(xm.ConfigPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	var content string
	if os.IsNotExist(err) || len(strings.TrimSpace(string(contentBytes))) == 0 {
		if err := os.MkdirAll(filepath.Dir(xm.ConfigPath), 0755); err != nil {
			return err
		}
		if xm.RootTag == "NetworkConfiguration" {
			content = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<NetworkConfiguration xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">\n</NetworkConfiguration>\n"
		} else {
			content = fmt.Sprintf("<%s>\n</%s>\n", xm.RootTag, xm.RootTag)
		}
	} else {
		content = string(contentBytes)
	}

	// Sort keys for deterministic output
	keys := make([]string, 0, len(settings))
	for k := range settings {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	closingTag := fmt.Sprintf("</%s>", xm.RootTag)

	for _, key := range keys {
		val := settings[key]

		// Special case for Jellyfin KnownProxies array element
		if key == "KnownProxies" && xm.RootTag == "NetworkConfiguration" {
			reKnown := regexp.MustCompile(`(?s)<KnownProxies\s*/>|<KnownProxies>.*?</KnownProxies>`)
			replacement := fmt.Sprintf("<KnownProxies>\n    <string>%s</string>\n  </KnownProxies>", val)
			if reKnown.MatchString(content) {
				content = reKnown.ReplaceAllString(content, replacement)
			} else if idx := strings.LastIndex(content, closingTag); idx != -1 {
				content = content[:idx] + "  " + replacement + "\n" + content[idx:]
			}
			continue
		}

		tagPattern := fmt.Sprintf(`(?s)<%s>.*?</%s>|<%s\s*/>`, regexp.QuoteMeta(key), regexp.QuoteMeta(key), regexp.QuoteMeta(key))
		reTag := regexp.MustCompile(tagPattern)
		newElement := fmt.Sprintf("<%s>%s</%s>", key, val, key)

		if reTag.MatchString(content) {
			content = reTag.ReplaceAllString(content, newElement)
		} else if idx := strings.LastIndex(content, closingTag); idx != -1 {
			content = content[:idx] + "  " + newElement + "\n" + content[idx:]
		}
	}

	return os.WriteFile(xm.ConfigPath, []byte(content), 0644)
}

// PiHoleMutator manages Pi-hole v6 (pihole.toml) and v5 (lighttpd/external.conf) web port settings.
type PiHoleMutator struct {
	ConfigPath string
}

func NewPiHoleMutator(path string) *PiHoleMutator {
	if path == "" {
		path = "/etc/pihole/pihole.toml"
	}
	return &PiHoleMutator{ConfigPath: path}
}

func (pm *PiHoleMutator) Backup() error {
	if _, err := os.Stat(pm.ConfigPath); os.IsNotExist(err) {
		return nil
	}
	return copyFileStruct(pm.ConfigPath, pm.ConfigPath+".bak")
}

func (pm *PiHoleMutator) Restore() error {
	if _, err := os.Stat(pm.ConfigPath + ".bak"); os.IsNotExist(err) {
		return nil
	}
	return copyFileStruct(pm.ConfigPath+".bak", pm.ConfigPath)
}

func (pm *PiHoleMutator) InjectRoutes(routes map[string]string) error {
	return pm.ApplyPortAndSettings(0, routes)
}

// ApplyPortAndSettings updates Pi-hole's web port in pihole.toml and/or lighttpd config if present.
func (pm *PiHoleMutator) ApplyPortAndSettings(port int, extra map[string]string) error {
	if pm.ConfigPath == "" {
		return nil
	}

	portStr := ""
	if port > 0 {
		portStr = fmt.Sprintf("%do", port)
	} else if p, ok := extra["webserver.port"]; ok && p != "" {
		portStr = p
	}

	if data, err := os.ReadFile(pm.ConfigPath); err == nil {
		content := string(data)
		if portStr != "" {
			rePort := regexp.MustCompile(`(?m)^(\s*port\s*=\s*)"[^"]*"`)
			if rePort.MatchString(content) {
				content = rePort.ReplaceAllString(content, fmt.Sprintf(`${1}"%s"`, portStr))
			} else {
				content += fmt.Sprintf("\n[webserver]\n  port = \"%s\"\n", portStr)
			}
		}
		if strings.EqualFold(extra["etc_dnsmasq_d"], "true") {
			reDnsmasq := regexp.MustCompile(`(?m)^(\s*etc_dnsmasq_d\s*=\s*)(?:true|false)`)
			if reDnsmasq.MatchString(content) {
				content = reDnsmasq.ReplaceAllString(content, `${1}true`)
			}
		}
		if err := os.WriteFile(pm.ConfigPath, []byte(content), 0644); err != nil {
			return err
		}
	}

	return nil
}
