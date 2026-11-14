package services

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5" // #nosec G501 -- legacy rTorrent/ruTorrent digest compatibility in memory only
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/crypto/pbkdf2"
)

const masterCredsEncPrefix = "enc:v1:"

type masterCredsPayload struct {
	Username string `json:"username"`
	Password string `json:"password"`
	HA1      string `json:"ha1,omitempty"`
}

func masterCredsPaths() []string {
	if custom := strings.TrimSpace(os.Getenv("AETHERFLOW_MASTER_CREDS_FILE")); custom != "" {
		return []string{custom}
	}
	return []string{
		resolveFilesystemPath("/var/lib/aetherflow/.master.creds"),
	}
}

func legacyDuplicateMasterCredsPaths() []string {
	return []string{
		resolveFilesystemPath("/opt/AetherFlow/backend/data/.master.creds"),
	}
}

func readLastAESKeyFromEnvFile(path string) string {
	cleaned := filepath.Clean(strings.TrimSpace(path))
	if cleaned == "" || !filepath.IsAbs(cleaned) {
		return ""
	}
	lst, err := os.Lstat(cleaned) // #nosec G703 -- validated absolute operator env file path
	if err != nil || lst.Mode()&os.ModeSymlink != 0 || !lst.Mode().IsRegular() {
		return ""
	}
	f, err := os.Open(cleaned) // #nosec G304,G703 -- validated regular non-symlink operator AETHERFLOW_ENV_FILE path
	if err != nil {
		return ""
	}
	defer f.Close()
	if fst, err := f.Stat(); err != nil || !fst.Mode().IsRegular() || !os.SameFile(lst, fst) {
		return ""
	}

	var last string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		if strings.HasPrefix(line, "AES_MASTER_KEY=") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "AES_MASTER_KEY="))
			val = strings.Trim(val, `"'`)
			if val != "" {
				last = val
			}
		}
	}
	return last
}

func resolveMasterCredsAESKey() ([]byte, bool) {
	rawEnv := os.Getenv("AES_MASTER_KEY")
	raw := strings.TrimSpace(rawEnv)
	if raw == "" && os.Getenv("AETHERFLOW_SKIP_ENV_FILES") != "1" {
		if envFile := strings.TrimSpace(os.Getenv("AETHERFLOW_ENV_FILE")); envFile != "" {
			raw = readLastAESKeyFromEnvFile(envFile)
		}
	}
	if raw == "" {
		return nil, false
	}
	if len(raw) == 64 {
		if decodedHex, err := hex.DecodeString(raw); err == nil && len(decodedHex) == 32 {
			return decodedHex, true
		}
	}
	if decoded, err := base64.StdEncoding.DecodeString(raw); err == nil && len(decoded) == 32 {
		return decoded, true
	}
	if len(raw) == 32 {
		return []byte(raw), true
	}
	if len(rawEnv) == 32 {
		return []byte(rawEnv), true
	}
	return nil, false
}

func encryptMasterCredsField(plaintext string) (string, error) {
	key, ok := resolveMasterCredsAESKey()
	if !ok {
		return plaintext, nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return masterCredsEncPrefix + base64.StdEncoding.EncodeToString(sealed), nil
}

func decryptMasterCredsField(stored string) (string, error) {
	trimmed := strings.TrimSpace(stored)
	if !strings.HasPrefix(trimmed, masterCredsEncPrefix) {
		return trimmed, nil
	}
	key, ok := resolveMasterCredsAESKey()
	if !ok {
		return "", errors.New("AES_MASTER_KEY required to decrypt master credentials")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(trimmed, masterCredsEncPrefix))
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}
	nonce, ciphertext := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func writeMasterCredsAtomically(targetPath string, content []byte) error {
	cleanTarget := filepath.Clean(targetPath)
	if fi, err := os.Lstat(cleanTarget); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symlink master credentials target: %s", cleanTarget)
	}
	dir := filepath.Dir(cleanTarget)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil { // #nosec G301 -- restricted 0700 state directory
			return err
		}
	}
	tmpFile, err := os.CreateTemp(dir, ".master.creds.tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmpFile.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmpFile.Chmod(0600); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if _, err := tmpFile.Write(content); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}
	// Verify target hasn't become a symlink right before rename
	if fd, openErr := syscall.Open(cleanTarget, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0); openErr == nil {
		_ = syscall.Close(fd)
	} else if !errors.Is(openErr, syscall.ENOENT) {
		return fmt.Errorf("unsafe master credentials destination %s: %w", cleanTarget, openErr)
	}
	if err := os.Rename(tmpName, cleanTarget); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func computeHA1Hex(password string) string {
	sum := md5.Sum([]byte(password)) // #nosec G401 -- legacy digest required in memory by downstream apps
	return hex.EncodeToString(sum[:])
}

// SaveMasterCredentials persists package-provisioning credentials (encrypted with AES-256-GCM
// when AES_MASTER_KEY is configured, without persisting an unencrypted MD5 HA1 digest) to
// /var/lib/aetherflow/.master.creds with mode 0600, removing legacy duplicate files.
func SaveMasterCredentials(username, password string) {
	u := strings.TrimSpace(username)
	if u == "" || password == "" || password == "adminadmin" {
		return
	}
	encPassword, err := encryptMasterCredsField(password)
	if err != nil {
		slog.Warn("unable to encrypt master credentials password", "error", err)
		return
	}

	payload := masterCredsPayload{
		Username: u,
		Password: encPassword,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return
	}
	raw = append(raw, '\n')

	wroteAny := false
	wroteAll := true
	for _, p := range masterCredsPaths() {
		if p == "" {
			continue
		}
		if err := writeMasterCredsAtomically(p, raw); err != nil {
			wroteAll = false
			slog.Debug("unable to write master credentials file", "path", p, "error", err)
		} else {
			wroteAny = true
		}
	}
	if wroteAny && wroteAll && strings.TrimSpace(os.Getenv("AETHERFLOW_MASTER_CREDS_FILE")) == "" {
		for _, legacy := range legacyDuplicateMasterCredsPaths() {
			_ = os.Remove(legacy)
		}
	}
}

func hasExistingEncryptedMasterCredsFile() bool {
	readPaths := append([]string{}, masterCredsPaths()...)
	if strings.TrimSpace(os.Getenv("AETHERFLOW_MASTER_CREDS_FILE")) == "" {
		readPaths = append(readPaths, legacyDuplicateMasterCredsPaths()...)
	}
	for _, p := range readPaths {
		if p == "" {
			continue
		}
		if data, err := os.ReadFile(p); err == nil && strings.Contains(string(data), masterCredsEncPrefix) { // #nosec G304 -- controlled internal credential store path
			return true
		}
	}
	return false
}

// DeriveAppWebUIPassword derives a domain-separated, irreversible 32-hex-character
// password for downstream apps whose configuration format requires plaintext values.
func DeriveAppWebUIPassword(appID, masterPass string) string {
	mac := hmac.New(sha256.New, []byte(masterPass))
	_, _ = mac.Write([]byte("aetherflow:" + strings.ToLower(strings.TrimSpace(appID)) + ":webui:v1"))
	return hex.EncodeToString(mac.Sum(nil)[:16])
}

// EnsureProvisioningMasterCredentials initializes dedicated random package-provisioning
// credentials if none exist yet, so the control-plane admin password is never written to disk,
// while refusing to clobber an existing encrypted .master.creds file on decryption failure.
func EnsureProvisioningMasterCredentials(username string) {
	u := strings.TrimSpace(username)
	if u == "" {
		u = "admin"
	}
	if existingUser, existingPass, _ := LoadMasterCredentials(); existingUser != "" && existingPass != "" && existingPass != "adminadmin" {
		SaveMasterCredentials(existingUser, existingPass)
		return
	}
	if hasExistingEncryptedMasterCredsFile() {
		slog.Warn("existing encrypted master credentials could not be decrypted; refusing to overwrite .master.creds")
		return
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		slog.Warn("failed to generate random provisioning secret", "error", err)
		return
	}
	SaveMasterCredentials(u, hex.EncodeToString(buf))
}

// LoadMasterCredentials loads the provisioning username, password, and computed MD5 HA1 digest
// from the persisted store or /install/.aetherflow.conf.
func LoadMasterCredentials() (username, password, ha1 string) {
	readPaths := append([]string{}, masterCredsPaths()...)
	if strings.TrimSpace(os.Getenv("AETHERFLOW_MASTER_CREDS_FILE")) == "" {
		readPaths = append(readPaths, legacyDuplicateMasterCredsPaths()...)
	}
	for _, p := range readPaths {
		if p == "" {
			continue
		}
		if data, err := os.ReadFile(p); err == nil && len(data) > 0 { // #nosec G304 -- controlled internal credential store path
			var payload masterCredsPayload
			if err := json.Unmarshal(data, &payload); err == nil && strings.TrimSpace(payload.Username) != "" && strings.TrimSpace(payload.Password) != "" {
				decPass, decErr := decryptMasterCredsField(payload.Password)
				if decErr == nil && decPass != "" && decPass != "adminadmin" {
					return strings.TrimSpace(payload.Username), decPass, computeHA1Hex(decPass)
				}
			}
		}
	}

	confPath := resolveFilesystemPath("/install/.aetherflow.conf")
	if f, err := os.Open(confPath); err == nil { // #nosec G304 -- controlled installer conf path
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

	if username != "" && password != "" && password != "adminadmin" {
		expectedHA1 := computeHA1Hex(password)
		if ha1 == "" || ha1 != expectedHA1 {
			ha1 = expectedHA1
		}
		return username, password, ha1
	}
	return "", "", ""
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
