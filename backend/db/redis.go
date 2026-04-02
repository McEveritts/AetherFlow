package db

import (
	"context"
	"log"
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
		log.Printf("WARNING: Redis is unavailable (%v). Falling back to in-memory JWT blacklist.", err)
		RedisClient = nil // Flag state to bypass Redis checks safely
	} else {
		log.Println("Redis connected successfully.")
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
