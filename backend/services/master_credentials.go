package services

import (
	"bufio"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

type masterCredsPayload struct {
	Username string `json:"username"`
	Password string `json:"password"`
	HA1      string `json:"ha1"`
}

func masterCredsPaths() []string {
	var paths []string
	if custom := strings.TrimSpace(os.Getenv("AETHERFLOW_MASTER_CREDS_FILE")); custom != "" {
		paths = append(paths, custom)
	}
	paths = append(paths,
		resolveFilesystemPath("/var/lib/aetherflow/.master.creds"),
		resolveFilesystemPath("/opt/AetherFlow/backend/data/.master.creds"),
	)
	return paths
}

// SaveMasterCredentials persists the master administrator username and password so that
// all package installers (packages/common.sh) and blueprint provisioners configure
// the same master account automatically across new servers, Web UI onboarding, and password updates.
func SaveMasterCredentials(username, password string) {
	u := strings.TrimSpace(username)
	if u == "" || password == "" {
		return
	}
	sum := md5.Sum([]byte(password))
	ha1 := hex.EncodeToString(sum[:])

	payload := masterCredsPayload{
		Username: u,
		Password: password,
		HA1:      ha1,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return
	}

	for _, p := range masterCredsPaths() {
		if p == "" {
			continue
		}
		if dir := filepath.Dir(p); dir != "" {
			_ = os.MkdirAll(dir, 0750)
		}
		if err := os.WriteFile(p, append(raw, '\n'), 0600); err != nil {
			slog.Debug("unable to write master credentials file", "path", p, "error", err)
		}
	}
}

// LoadMasterCredentials loads the master administrator username, password, and MD5 HA1 digest
// from the persisted JSON store or /install/.aetherflow.conf.
func LoadMasterCredentials() (username, password, ha1 string) {
	for _, p := range masterCredsPaths() {
		if p == "" {
			continue
		}
		if data, err := os.ReadFile(p); err == nil && len(data) > 0 {
			var payload masterCredsPayload
			if err := json.Unmarshal(data, &payload); err == nil && payload.Username != "" && payload.Password != "" {
				if payload.HA1 == "" {
					sum := md5.Sum([]byte(payload.Password))
					payload.HA1 = hex.EncodeToString(sum[:])
				}
				return payload.Username, payload.Password, payload.HA1
			}
		}
	}

	confPath := resolveFilesystemPath("/install/.aetherflow.conf")
	if f, err := os.Open(confPath); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			val := unescapeBashPrintfQ(strings.TrimSpace(v))
			switch strings.TrimSpace(k) {
			case "username":
				username = val
			case "passwd":
				password = val
			case "ha1pass":
				ha1 = val
			}
		}
	}

	if username != "" && password != "" && ha1 == "" {
		sum := md5.Sum([]byte(password))
		ha1 = hex.EncodeToString(sum[:])
	}
	return username, password, ha1
}

// unescapeBashPrintfQ reverses bash `printf '%q'` escaping used by _save_config in 06-state.sh.
func unescapeBashPrintfQ(raw string) string {
	if len(raw) >= 2 && ((raw[0] == '\'' && raw[len(raw)-1] == '\'') || (raw[0] == '"' && raw[len(raw)-1] == '"')) {
		return raw[1 : len(raw)-1]
	}
	var b strings.Builder
	b.Grow(len(raw))
	for i := 0; i < len(raw); i++ {
		if raw[i] == '\\' && i+1 < len(raw) {
			i++
		}
		b.WriteByte(raw[i])
	}
	return b.String()
}

// GenerateQBittorrentPBKDF2 generates a qBittorrent v4.2+ WebUI\Password_PBKDF2 string
// formatted as "@ByteArray(<salt_b64>:<dk_b64>)" using 100,000 iterations of PBKDF2-HMAC-SHA512.
func GenerateQBittorrentPBKDF2(password string) string {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		copy(salt, []byte("aetherflowqbsalt"))
	}
	dk := pbkdf2.Key([]byte(password), salt, 100000, 64, sha512.New)
	return fmt.Sprintf(`"@ByteArray(%s:%s)"`,
		base64.StdEncoding.EncodeToString(salt),
		base64.StdEncoding.EncodeToString(dk),
	)
}
