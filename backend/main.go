package main

import (
	"log"
	"os"

	"aetherflow/api"
	"aetherflow/db"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	// Try loading .env from local or parent directory
	if err := godotenv.Load("../.env"); err != nil {
		godotenv.Load() // fallback to current dir if any
	}

	// Initialize the Database
	db.InitDB()

	r := gin.Default()

	// Enable Wide CORS for local frontend development
	// Ensure we only allow strictly defined origins via Env
	allowedOrigins := []string{"http://127.0.0.1:3000", "http://localhost:3000"}
	if customOrigin := os.Getenv("ALLOWED_CORS_ORIGIN"); customOrigin != "" {
		allowedOrigins = append(allowedOrigins, customOrigin)
	}

	r.Use(cors.New(cors.Config{
		AllowOrigins:     allowedOrigins,
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	// Register all API routes from the api package
	api.RegisterRoutes(r)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("AetherFlow Backend listening on 127.0.0.1:%s", port)
	
	// Bind to localhost to prevent direct internet exposure
	if err := r.Run("127.0.0.1:" + port); err != nil {
		log.Fatalf("Failed to run server: %v", err)
	}
}
