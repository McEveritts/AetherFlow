package db

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
)

var RedisClient *redis.Client

func InitRedis() {
	RedisClient = redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: os.Getenv("REDIS_PASSWORD"),
		DB:       0,
		PoolSize: 100, // Robust connection pool
	})

	// Graceful degradation check
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := RedisClient.Ping(ctx).Err(); err != nil {
		log.Printf("WARNING: Redis is unavailable (%v). Session revocation checks will degrade open.", err)
		RedisClient = nil // Flag state to bypass Redis checks safely
	} else {
		log.Println("Redis connected successfully.")
	}
}

func RevokeToken(jti string, expiration time.Duration) error {
	if RedisClient == nil {
		return nil // Fail-open / degrade gracefully if Redis is unsupported
	}
	ctx := context.Background()
	// TTL exactly matches remaining lifespan to optimize memory
	return RedisClient.Set(ctx, "blacklist:"+jti, "true", expiration).Err()
}
