package db

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

var RedisClient *redis.Client

var (
	localBlacklist sync.Map // fallback in-memory blacklist
)

// InitRedis initializes the Redis client or falls back to in-memory mode
func InitRedis() {
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		addr = "localhost:6379"
	}

	RedisClient = redis.NewClient(&redis.Options{
		Addr:         addr,
		Password:     os.Getenv("REDIS_PASSWORD"),
		DB:           0,
		PoolSize:     100,
		MinIdleConns: 10,
		DialTimeout:  2 * time.Second,
		ReadTimeout:  500 * time.Millisecond,
		WriteTimeout: 500 * time.Millisecond,
	})

	// Graceful degradation check
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := RedisClient.Ping(ctx).Err(); err != nil {
		slog.Warn("Redis unavailable, falling back to in-memory JWT blacklist", "error", err)
		RedisClient = nil // Flag state to bypass Redis checks safely
	} else {
		slog.Info("Redis connected successfully.")
	}

	// Start background cleanup for localBlacklist, pending2FACache, and mfaChallengeCache
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			SweepExpiredAuthCaches(time.Now().Unix())
		}
	}()
}

// SweepExpiredAuthCaches evicts expired entries from all in-process auth fallback maps
// and prunes expired SQLite mfa_challenges / revoked_tokens rows.
func SweepExpiredAuthCaches(nowUnix int64) {
	localBlacklist.Range(func(key, value interface{}) bool {
		exp, ok := value.(int64)
		if !ok || nowUnix > exp {
			localBlacklist.Delete(key)
		}
		return true
	})
	pending2FACache.Range(func(key, value interface{}) bool {
		entry, ok := value.(pending2FAEntry)
		if !ok || nowUnix > entry.ExpiresAt {
			pending2FACache.Delete(key)
		}
		return true
	})
	mfaChallengeCache.Range(func(key, value interface{}) bool {
		entry, ok := value.(mfaChallengeEntry)
		if !ok || nowUnix > entry.ExpiresAt {
			mfaChallengeCache.Delete(key)
		}
		return true
	})
	if DB != nil {
		_, _ = DB.Exec("DELETE FROM mfa_challenges WHERE expires_at <= ?", nowUnix)
		_, _ = DB.Exec(
			"DELETE FROM revoked_tokens WHERE expires_at IS NOT NULL AND TRIM(expires_at) != '' AND datetime(expires_at) IS NOT NULL AND datetime(expires_at) <= datetime('now')",
		)
	}
}

// minRevocationTTL enforces a minimum 136-minute (8160s) floor on JTI revocations so a newly minted
// 15-minute access token remains revoked across its entire 2-hour post-expiry refresh grace window
// plus 60 seconds of clock-skew tolerance.
const minRevocationTTL = 136 * time.Minute

// MaxMFAAttempts bounds failed second-factor verification attempts per MFA challenge token across all IPs.
const MaxMFAAttempts = 5

// ClearLocalBlacklist resets the in-process revocation and MFA caches (used during DB re-initialization in tests).
func ClearLocalBlacklist() {
	localBlacklist.Range(func(key, _ interface{}) bool {
		localBlacklist.Delete(key)
		return true
	})
	pending2FACache.Range(func(key, _ interface{}) bool {
		pending2FACache.Delete(key)
		return true
	})
	mfaChallengeCache.Range(func(key, _ interface{}) bool {
		mfaChallengeCache.Delete(key)
		return true
	})
}

func normalizeRevocationTTL(expiration time.Duration) time.Duration {
	if expiration < minRevocationTTL {
		return minRevocationTTL
	}
	return expiration
}

// CacheRevokedToken populates the in-memory and optional Redis revocation caches after a SQLite transaction commits.
func CacheRevokedToken(jti string, expiration time.Duration) {
	if jti == "" {
		return
	}
	expiration = normalizeRevocationTTL(expiration)
	now := time.Now().UTC()
	localBlacklist.Store(jti, now.Add(expiration).Unix())
	if RedisClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = RedisClient.Set(ctx, "blacklist:"+jti, "true", expiration).Err()
	}
}

// RevokeTokenInTx persists a JTI revocation inside an open SQLite transaction without mutating
// in-memory state prior to commit. Call CacheRevokedToken after tx.Commit() succeeds.
func RevokeTokenInTx(tx *sql.Tx, jti string, expiration time.Duration) error {
	if jti == "" || tx == nil {
		return nil
	}
	expiration = normalizeRevocationTTL(expiration)
	expiresAt := time.Now().UTC().Add(expiration).Format(time.RFC3339)
	if _, err := tx.Exec(
		`INSERT INTO revoked_tokens (jti, expires_at) VALUES (?, ?)
		 ON CONFLICT(jti) DO UPDATE SET expires_at = excluded.expires_at`,
		jti, expiresAt,
	); err != nil {
		return fmt.Errorf("failed to persist revoked token in tx: %w", err)
	}
	return nil
}

// RecordRevokedTokenLineageInTx records durable (family_id, user_id) lineage on a consumed/revoked JTI
// so intermediate refresh-token replay after a process restart can still locate and wipe active descendants.
func RecordRevokedTokenLineageInTx(tx *sql.Tx, jti, familyID string, userID int, expiration time.Duration) error {
	if jti == "" || tx == nil {
		return nil
	}
	expiration = normalizeRevocationTTL(expiration)
	expiresAt := time.Now().UTC().Add(expiration).Format(time.RFC3339)
	_, err := tx.Exec(
		`INSERT INTO revoked_tokens (jti, expires_at, family_id, user_id) VALUES (?, ?, ?, ?)
		 ON CONFLICT(jti) DO UPDATE SET
		     expires_at = excluded.expires_at,
		     family_id = CASE WHEN excluded.family_id != '' THEN excluded.family_id ELSE revoked_tokens.family_id END,
		     user_id = CASE WHEN excluded.user_id > 0 THEN excluded.user_id ELSE revoked_tokens.user_id END`,
		jti, expiresAt, strings.TrimSpace(familyID), userID,
	)
	if err != nil && strings.Contains(err.Error(), "no such column") {
		return RevokeTokenInTx(tx, jti, expiration)
	}
	if err != nil {
		return fmt.Errorf("failed to persist revoked token lineage in tx: %w", err)
	}
	return nil
}

// ResolveRevokedTokenFamilyInTx looks up durable family_id recorded when an intermediate JTI was rotated.
func ResolveRevokedTokenFamilyInTx(tx *sql.Tx, userID int, jti string) string {
	if tx == nil || jti == "" {
		return ""
	}
	var familyID string
	err := tx.QueryRow(
		"SELECT COALESCE(family_id, '') FROM revoked_tokens WHERE jti = ? AND (user_id = ? OR user_id = 0) LIMIT 1",
		jti, userID,
	).Scan(&familyID)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(familyID)
}

// TryConsumeTokenInTx atomically marks a JTI as consumed/revoked inside an open SQLite transaction.
// Returns (true, nil) exclusively for the single winning caller when the JTI was not already un-expired
// in revoked_tokens; returns (false, nil) if already consumed/revoked.
func TryConsumeTokenInTx(tx *sql.Tx, jti string, expiration time.Duration) (bool, error) {
	if strings.TrimSpace(jti) == "" || tx == nil {
		return false, fmt.Errorf("empty jti or nil transaction")
	}
	expiration = normalizeRevocationTTL(expiration)
	expiresAt := time.Now().UTC().Add(expiration).Format(time.RFC3339)
	res, err := tx.Exec(
		`INSERT INTO revoked_tokens (jti, expires_at) VALUES (?, ?)
		 ON CONFLICT(jti) DO UPDATE SET expires_at = excluded.expires_at
		 WHERE revoked_tokens.expires_at IS NOT NULL
		   AND TRIM(revoked_tokens.expires_at) != ''
		   AND datetime(revoked_tokens.expires_at) IS NOT NULL
		   AND datetime(revoked_tokens.expires_at) <= datetime('now')`,
		jti, expiresAt,
	)
	if err != nil {
		return false, fmt.Errorf("failed to consume token in tx: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to check rows affected: %w", err)
	}
	return rows == 1, nil
}

// RevokeToken adds a token's JTI to the blacklist with a given expiration.
func RevokeToken(jti string, expiration time.Duration) error {
	if jti == "" {
		return nil
	}
	expiration = normalizeRevocationTTL(expiration)

	now := time.Now().UTC()
	expTime := now.Add(expiration).Unix()
	localBlacklist.Store(jti, expTime) // Always store locally for immediate consistency/failover

	if DB != nil {
		expiresAt := now.Add(expiration).Format(time.RFC3339)
		if _, err := DB.Exec(
			`INSERT INTO revoked_tokens (jti, expires_at) VALUES (?, ?)
			 ON CONFLICT(jti) DO UPDATE SET expires_at = excluded.expires_at`,
			jti, expiresAt,
		); err != nil {
			return fmt.Errorf("failed to persist revoked token: %w", err)
		}
	}

	if RedisClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		// TTL matches remaining/grace lifespan
		return RedisClient.Set(ctx, "blacklist:"+jti, "true", expiration).Err()
	}
	return nil
}

// IsTokenRevokedCached checks only the in-memory and optional Redis revocation caches
// without acquiring a SQLite connection (safe to call while holding an open *sql.Tx).
func parseRevokedExpiresAt(raw string) (time.Time, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
	} {
		if parsed, err := time.Parse(layout, trimmed); err == nil {
			return parsed.UTC(), true
		}
	}
	return time.Time{}, false
}

// IsTokenRevokedInTx checks inside an open SQLite transaction whether jti is currently revoked,
// failing closed (true) on empty jti, SQL errors, or malformed/empty expires_at timestamps.
func IsTokenRevokedInTx(tx *sql.Tx, jti string) bool {
	trimmed := strings.TrimSpace(jti)
	if trimmed == "" || tx == nil {
		return true
	}
	var rawExpires string
	err := tx.QueryRow(
		"SELECT COALESCE(expires_at, '') FROM revoked_tokens WHERE jti = ? LIMIT 1",
		trimmed,
	).Scan(&rawExpires)
	if err == sql.ErrNoRows {
		return false
	}
	if err != nil {
		return true
	}
	parsedExp, ok := parseRevokedExpiresAt(rawExpires)
	if !ok {
		return true
	}
	return time.Now().UTC().Before(parsedExp)
}

func IsTokenRevokedCached(jti string) bool {
	trimmed := strings.TrimSpace(jti)
	if trimmed == "" {
		return true
	}

	if expRaw, ok := localBlacklist.Load(trimmed); ok {
		if exp, ok := expRaw.(int64); ok && time.Now().Unix() <= exp {
			return true
		}
		localBlacklist.Delete(trimmed)
	}

	if RedisClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		if RedisClient.Get(ctx, "blacklist:"+trimmed).Err() == nil {
			return true
		}
	}

	return false
}

// IsTokenRevoked checks if a JWT was blacklisted, failing closed on empty JTI or corrupt timestamps.
func IsTokenRevoked(jti string) bool {
	trimmed := strings.TrimSpace(jti)
	if trimmed == "" {
		return true
	}

	if IsTokenRevokedCached(trimmed) {
		return true
	}

	if DB != nil {
		var rawExpires string
		err := DB.QueryRow(
			"SELECT COALESCE(expires_at, '') FROM revoked_tokens WHERE jti = ? LIMIT 1",
			trimmed,
		).Scan(&rawExpires)
		if err == sql.ErrNoRows {
			return false
		}
		if err != nil {
			slog.Error("Revocation check failed closed due to SQLite error", "jti", trimmed, "error", err)
			return true
		}
		parsedExp, ok := parseRevokedExpiresAt(rawExpires)
		if !ok {
			slog.Warn("Revocation check failed closed due to malformed expires_at", "jti", trimmed)
			return true
		}
		if !time.Now().UTC().Before(parsedExp) {
			return false
		}
		localBlacklist.Store(trimmed, parsedExp.Unix())
		return true
	}
	return false
}

// ── 2FA Pending Secret Cache ──────────────────────────────────────────────

var pending2FACache sync.Map // fallback: userID → {secret string, expiresAt int64}

type pending2FAEntry struct {
	Secret    string
	ExpiresAt int64
}

// Store2FAPending stores a pending TOTP secret with a TTL.
// Uses Redis ("2fa_pending:<userID>") with an in-memory fallback.
func Store2FAPending(userID int, secret string, ttl time.Duration) error {
	key := fmt.Sprintf("2fa_pending:%d", userID)
	entry := pending2FAEntry{Secret: secret, ExpiresAt: time.Now().Add(ttl).Unix()}
	pending2FACache.Store(key, entry)

	if RedisClient != nil {
		ctx := context.Background()
		return RedisClient.Set(ctx, key, secret, ttl).Err()
	}
	return nil
}

// Get2FAPending retrieves a pending TOTP secret.
func Get2FAPending(userID int) (string, error) {
	key := fmt.Sprintf("2fa_pending:%d", userID)

	// Try local cache first
	if raw, ok := pending2FACache.Load(key); ok {
		entry, ok := raw.(pending2FAEntry)
		if ok && time.Now().Unix() <= entry.ExpiresAt {
			return entry.Secret, nil
		}
		pending2FACache.Delete(key) // expired
	}

	// Try Redis
	if RedisClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		val, err := RedisClient.Get(ctx, key).Result()
		if err == nil {
			return val, nil
		}
	}

	return "", fmt.Errorf("no pending 2FA secret found")
}

// Delete2FAPending removes a pending TOTP secret after successful verification.
func Delete2FAPending(userID int) {
	key := fmt.Sprintf("2fa_pending:%d", userID)
	pending2FACache.Delete(key)

	if RedisClient != nil {
		ctx := context.Background()
		RedisClient.Del(ctx, key)
	}
}

// ── MFA Login Challenge Store ─────────────────────────────────────────────
// Bridges first-factor authentication and second-factor TOTP/recovery verification.
// Persisted in SQLite `mfa_challenges` with per-challenge attempt caps and credential-epoch
// binding, with synchronized in-memory/Redis fallback when DB is nil in isolated unit tests.

var (
	mfaChallengeCache sync.Map
	mfaChallengeMu    sync.Mutex
)

type mfaChallengeEntry struct {
	UserID        int
	CredentialVer int64
	Attempts      int
	ExpiresAt     int64
}

func clampMFATTLSeconds(ttl time.Duration) int64 {
	secs := int64(ttl.Seconds())
	if secs <= 0 || secs > 300 {
		return 300
	}
	return secs
}

// StoreMFAChallengeWithEpochInTx persists a first-factor MFA challenge bound to credentialVer inside tx.
func StoreMFAChallengeWithEpochInTx(tx *sql.Tx, token string, userID int, credentialVer int64, ttl time.Duration) error {
	if token == "" || tx == nil {
		return fmt.Errorf("empty mfa token or nil transaction")
	}
	now := time.Now().UTC().Unix()
	expiresAt := now + clampMFATTLSeconds(ttl)
	_, _ = tx.Exec("DELETE FROM mfa_challenges WHERE expires_at <= ?", now)
	_, err := tx.Exec(
		"INSERT INTO mfa_challenges (token, user_id, attempts, expires_at, credential_ver) VALUES (?, ?, 0, ?, ?)",
		token, userID, expiresAt, credentialVer,
	)
	if err != nil && strings.Contains(err.Error(), "no such column") {
		_, err = tx.Exec(
			"INSERT INTO mfa_challenges (token, user_id, attempts, expires_at) VALUES (?, ?, 0, ?)",
			token, userID, expiresAt,
		)
	}
	if err != nil {
		return fmt.Errorf("failed to persist MFA challenge in tx: %w", err)
	}
	return nil
}

// CacheMFAChallengeWithEpoch updates the in-memory and optional Redis caches after tx.Commit().
func CacheMFAChallengeWithEpoch(token string, userID int, credentialVer int64, ttl time.Duration) {
	if token == "" {
		return
	}
	secs := clampMFATTLSeconds(ttl)
	clampedTTL := time.Duration(secs) * time.Second
	key := "mfa_challenge:" + token
	mfaChallengeCache.Store(key, mfaChallengeEntry{
		UserID:        userID,
		CredentialVer: credentialVer,
		Attempts:      0,
		ExpiresAt:     time.Now().UTC().Unix() + secs,
	})
	if RedisClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = RedisClient.Set(ctx, key, fmt.Sprintf("%d:%d", userID, credentialVer), clampedTTL).Err()
	}
}

// StoreMFAChallenge stores a challenge token mapping to a user ID bound to the user's current credential epoch.
func StoreMFAChallenge(token string, userID int, ttl time.Duration) error {
	if token == "" {
		return fmt.Errorf("empty mfa token")
	}
	var credentialVer int64
	if DB != nil {
		_ = DB.QueryRow("SELECT COALESCE(sessions_revoked_after, 0) FROM users WHERE id = ?", userID).Scan(&credentialVer)
		tx, err := DB.Begin()
		if err != nil {
			return fmt.Errorf("failed to begin MFA challenge transaction: %w", err)
		}
		if err := StoreMFAChallengeWithEpochInTx(tx, token, userID, credentialVer, ttl); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("failed to commit MFA challenge: %w", err)
		}
	}
	CacheMFAChallengeWithEpoch(token, userID, credentialVer, ttl)
	return nil
}

// DeleteUserMFAChallengesInTx purges all pending MFA challenges for userID inside an open transaction.
func DeleteUserMFAChallengesInTx(tx *sql.Tx, userID int) error {
	if tx == nil || userID <= 0 {
		return nil
	}
	_, err := tx.Exec("DELETE FROM mfa_challenges WHERE user_id = ?", userID)
	if err != nil && strings.Contains(err.Error(), "no such table") {
		return nil
	}
	return err
}

// DeleteUserMFAChallengesCache purges all cached MFA challenges belonging to userID after commit.
func DeleteUserMFAChallengesCache(userID int) {
	var tokens []string
	mfaChallengeCache.Range(func(key, value interface{}) bool {
		entry, ok := value.(mfaChallengeEntry)
		if ok && entry.UserID == userID {
			if k, isStr := key.(string); isStr {
				tokens = append(tokens, k)
			}
			mfaChallengeCache.Delete(key)
		}
		return true
	})
	if RedisClient != nil && len(tokens) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = RedisClient.Del(ctx, tokens...).Err()
	}
}

// BeginMFAAttemptWithEpochInTx atomically increments the attempt counter for token inside tx
// while enforcing MaxMFAAttempts and expiry, returning (userID, credentialVer, ok, err).
// Callers MUST commit tx on failed factor verification so attempt accounting is durable.
func BeginMFAAttemptWithEpochInTx(tx *sql.Tx, token string) (int, int64, bool, error) {
	if token == "" || tx == nil {
		return 0, 0, false, nil
	}
	now := time.Now().UTC().Unix()
	var userID int
	var credentialVer int64
	err := tx.QueryRow(
		`UPDATE mfa_challenges
		    SET attempts = attempts + 1
		  WHERE token = ? AND attempts < ? AND expires_at > ?
		  RETURNING user_id, COALESCE(credential_ver, 0)`,
		token, MaxMFAAttempts, now,
	).Scan(&userID, &credentialVer)
	if err != nil && strings.Contains(err.Error(), "no such column") {
		err = tx.QueryRow(
			`UPDATE mfa_challenges
			    SET attempts = attempts + 1
			  WHERE token = ? AND attempts < ? AND expires_at > ?
			  RETURNING user_id`,
			token, MaxMFAAttempts, now,
		).Scan(&userID)
		credentialVer = 0
	}
	if err == sql.ErrNoRows {
		_, _ = tx.Exec("DELETE FROM mfa_challenges WHERE token = ? AND (attempts >= ? OR expires_at <= ?)", token, MaxMFAAttempts, now)
		return 0, 0, false, nil
	}
	if err != nil {
		return 0, 0, false, err
	}
	return userID, credentialVer, true, nil
}

// ConsumeMFAChallengeWithEpochInTx atomically deletes a verified MFA challenge bound to (userID, credentialVer)
// inside tx, returning true exclusively for the single winning redemption within MaxMFAAttempts.
func ConsumeMFAChallengeWithEpochInTx(tx *sql.Tx, token string, userID int, credentialVer int64) (bool, error) {
	if token == "" || tx == nil || userID <= 0 {
		return false, nil
	}
	now := time.Now().UTC().Unix()
	res, err := tx.Exec(
		`DELETE FROM mfa_challenges
		  WHERE token = ? AND user_id = ? AND COALESCE(credential_ver, 0) = ?
		    AND attempts <= ? AND expires_at > ?`,
		token, userID, credentialVer, MaxMFAAttempts, now,
	)
	if err != nil && strings.Contains(err.Error(), "no such column") {
		res, err = tx.Exec(
			`DELETE FROM mfa_challenges
			  WHERE token = ? AND user_id = ? AND attempts <= ? AND expires_at > ?`,
			token, userID, MaxMFAAttempts, now,
		)
	}
	if err != nil {
		return false, err
	}
	rows, rErr := res.RowsAffected()
	if rErr != nil {
		return false, rErr
	}
	return rows == 1, nil
}

// GetMFAChallenge retrieves the user ID for an active, unexhausted challenge token.
func GetMFAChallenge(token string) (int, error) {
	now := time.Now().UTC().Unix()
	if DB != nil {
		var uid int
		err := DB.QueryRow(
			"SELECT user_id FROM mfa_challenges WHERE token = ? AND expires_at > ? AND attempts < ?",
			token, now, MaxMFAAttempts,
		).Scan(&uid)
		if err == nil && uid > 0 {
			return uid, nil
		}
		if err == sql.ErrNoRows {
			return 0, fmt.Errorf("MFA challenge expired or not found")
		}
		if err != nil {
			return 0, fmt.Errorf("MFA challenge lookup failed: %w", err)
		}
		return 0, fmt.Errorf("MFA challenge expired or not found")
	}

	key := "mfa_challenge:" + token
	mfaChallengeMu.Lock()
	raw, ok := mfaChallengeCache.Load(key)
	if ok {
		entry, valid := raw.(mfaChallengeEntry)
		if valid && now <= entry.ExpiresAt && entry.Attempts < MaxMFAAttempts {
			mfaChallengeMu.Unlock()
			return entry.UserID, nil
		}
		mfaChallengeCache.Delete(key)
	}
	mfaChallengeMu.Unlock()

	if RedisClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		val, err := RedisClient.Get(ctx, key).Result()
		if err == nil {
			var uid int
			if _, err := fmt.Sscanf(val, "%d", &uid); err == nil && uid > 0 {
				return uid, nil
			}
		}
	}

	return 0, fmt.Errorf("MFA challenge expired or not found")
}

// EvictMFAChallengeCache clears a challenge token from in-memory and Redis caches without touching SQLite.
func EvictMFAChallengeCache(token string) {
	key := "mfa_challenge:" + token
	mfaChallengeCache.Delete(key)
	if RedisClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = RedisClient.Del(ctx, key).Err()
	}
}

// DeleteMFAChallenge removes a challenge token from SQLite, in-memory cache, and Redis.
func DeleteMFAChallenge(token string) {
	if DB != nil && token != "" {
		_, _ = DB.Exec("DELETE FROM mfa_challenges WHERE token = ?", token)
	}
	EvictMFAChallengeCache(token)
}
