package db

import (
	"context"
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

// RevokeToken adds a token's JTI to the blacklist with a given expiration.
func RevokeToken(jti string, expiration time.Duration) error {
	expTime := time.Now().Add(expiration).Unix()
	localBlacklist.Store(jti, expTime) // Always store locally for immediate consistency/failover

	if RedisClient != nil {
		ctx := context.Background()
		// TTL exactly matches remaining lifespan to optimize memory
		return RedisClient.Set(ctx, "blacklist:"+jti, "true", expiration).Err()
	}
	return nil
}

// IsTokenRevoked checks if a JWT was blacklisted
func IsTokenRevoked(jti string) bool {
	// Fast local path
	if expRaw, ok := localBlacklist.Load(jti); ok {
		if exp, ok := expRaw.(int64); ok && time.Now().Unix() <= exp {
			return true // Positively blacklisted locally
		} else {
			localBlacklist.Delete(jti) // Cleanup expired
		}
	}

	if RedisClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		if RedisClient.Get(ctx, "blacklist:"+jti).Err() == nil {
			// Found in Redis
			return true
		}
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
