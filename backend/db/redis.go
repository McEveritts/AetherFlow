package db

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
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

	// Start background cleanup for localBlacklist
	go func() {
		for {
			time.Sleep(10 * time.Minute)
			now := time.Now().Unix()
			localBlacklist.Range(func(key, value interface{}) bool {
				exp, ok := value.(int64)
				if !ok || now > exp {
					localBlacklist.Delete(key)
				}
				return true
			})
		}
	}()
}

// minRevocationTTL enforces a minimum 136-minute (8160s) floor on JTI revocations so a newly minted
// 15-minute access token remains revoked across its entire 2-hour post-expiry refresh grace window
// plus 60 seconds of clock-skew tolerance.
const minRevocationTTL = 136 * time.Minute

// ClearLocalBlacklist resets the in-process revocation cache (used during DB re-initialization in tests).
func ClearLocalBlacklist() {
	localBlacklist.Range(func(key, _ interface{}) bool {
		localBlacklist.Delete(key)
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
		"INSERT OR REPLACE INTO revoked_tokens (jti, expires_at) VALUES (?, ?)",
		jti, expiresAt,
	); err != nil {
		return fmt.Errorf("failed to persist revoked token in tx: %w", err)
	}
	return nil
}

// TryConsumeTokenInTx atomically marks a JTI as consumed/revoked inside an open SQLite transaction.
// Returns (true, nil) exclusively for the single winning caller when the JTI was not already un-expired
// in revoked_tokens; returns (false, nil) if already consumed/revoked.
func TryConsumeTokenInTx(tx *sql.Tx, jti string, expiration time.Duration) (bool, error) {
	if jti == "" || tx == nil {
		return false, fmt.Errorf("empty jti or nil transaction")
	}
	expiration = normalizeRevocationTTL(expiration)
	expiresAt := time.Now().UTC().Add(expiration).Format(time.RFC3339)
	res, err := tx.Exec(
		`INSERT INTO revoked_tokens (jti, expires_at) VALUES (?, ?)
		 ON CONFLICT(jti) DO UPDATE SET expires_at = excluded.expires_at
		 WHERE revoked_tokens.expires_at IS NULL
		    OR TRIM(revoked_tokens.expires_at) = ''
		    OR datetime(revoked_tokens.expires_at) IS NULL
		    OR datetime(revoked_tokens.expires_at) <= datetime('now')`,
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
			"INSERT OR REPLACE INTO revoked_tokens (jti, expires_at) VALUES (?, ?)",
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
func IsTokenRevokedCached(jti string) bool {
	if jti == "" {
		return false
	}

	if expRaw, ok := localBlacklist.Load(jti); ok {
		if exp, ok := expRaw.(int64); ok && time.Now().Unix() <= exp {
			return true
		}
		localBlacklist.Delete(jti)
	}

	if RedisClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		if RedisClient.Get(ctx, "blacklist:"+jti).Err() == nil {
			return true
		}
	}

	return false
}

// IsTokenRevoked checks if a JWT was blacklisted
func IsTokenRevoked(jti string) bool {
	if jti == "" {
		return false
	}

	if IsTokenRevokedCached(jti) {
		return true
	}

	if DB != nil {
		var one int
		err := DB.QueryRow(
			"SELECT 1 FROM revoked_tokens WHERE jti = ? AND datetime(expires_at) > datetime('now') LIMIT 1",
			jti,
		).Scan(&one)
		if err == sql.ErrNoRows {
			return false
		}
		if err != nil {
			slog.Error("Revocation check failed closed due to SQLite error", "jti", jti, "error", err)
			return true
		}
		localBlacklist.Store(jti, time.Now().Add(2*time.Hour).Unix())
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

// ── MFA Login Challenge Cache ─────────────────────────────────────────────
// These bridge the gap between password verification and TOTP verification
// during login. The mfa_token is an opaque challenge proving password was valid.

var mfaChallengeCache sync.Map // fallback: token → {userID int, expiresAt int64}

type mfaChallengeEntry struct {
	UserID    int
	ExpiresAt int64
}

// StoreMFAChallenge stores a challenge token mapping to a user ID.
func StoreMFAChallenge(token string, userID int, ttl time.Duration) error {
	key := "mfa_challenge:" + token
	entry := mfaChallengeEntry{UserID: userID, ExpiresAt: time.Now().Add(ttl).Unix()}
	mfaChallengeCache.Store(key, entry)

	if RedisClient != nil {
		ctx := context.Background()
		return RedisClient.Set(ctx, key, fmt.Sprintf("%d", userID), ttl).Err()
	}
	return nil
}

// GetMFAChallenge retrieves the user ID for a challenge token.
func GetMFAChallenge(token string) (int, error) {
	key := "mfa_challenge:" + token

	// Try local cache first
	if raw, ok := mfaChallengeCache.Load(key); ok {
		entry, ok := raw.(mfaChallengeEntry)
		if ok && time.Now().Unix() <= entry.ExpiresAt {
			return entry.UserID, nil
		}
		mfaChallengeCache.Delete(key) // expired
	}

	// Try Redis
	if RedisClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		val, err := RedisClient.Get(ctx, key).Result()
		if err == nil {
			var uid int
			if _, err := fmt.Sscanf(val, "%d", &uid); err == nil {
				return uid, nil
			}
		}
	}

	return 0, fmt.Errorf("MFA challenge expired or not found")
}

// DeleteMFAChallenge removes a challenge token after successful verification.
func DeleteMFAChallenge(token string) {
	key := "mfa_challenge:" + token
	mfaChallengeCache.Delete(key)

	if RedisClient != nil {
		ctx := context.Background()
		RedisClient.Del(ctx, key)
	}
}
