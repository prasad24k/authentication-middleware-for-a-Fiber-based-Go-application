package main

import (
	"authentication/db"
	"authentication/security"
	"authentication/user"
	"fmt"
	"log"
	"os"

	"github.com/go-redis/redis"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/joho/godotenv"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	// Load env vars from .env file
	errEnv := godotenv.Load()
	if errEnv != nil {
		log.Fatal("Error loading .env file")
	}

	// Connect DB
	database, err := db.ConnectDB()
	if err != nil {
		log.Fatal("Failed to connect to DB:", err)
	}
	defer database.Close()

	// Port and origins from env
	serverPort := os.Getenv("SERVER_PORT")
	allowOrigins := os.Getenv("ALLOW_ORIGINS")

	// Redis config from env
	redisHost := os.Getenv("REDIS_HOST")
	redisPort := os.Getenv("REDIS_PORT")
	// Redis connection
	connectionRedisString := fmt.Sprintf("%s:%s", redisHost, redisPort)
	redisClient := redis.NewClient(&redis.Options{
		Addr: connectionRedisString,
	})

	// Service initializations
	userServer := user.Server{DB: database}
	securityInit := &security.Server{DB: database, RedisClient: redisClient}

	// Initialize Fiber app
	app := fiber.New(fiber.Config{
		BodyLimit: 60 * 1024 * 1024,
		Prefork:   false,
		Immutable: true,
	})

	// CORS Middleware
	app.Use(cors.New(cors.Config{
		AllowOrigins:     allowOrigins,
		AllowMethods:     "GET, POST, PUT, OPTIONS",
		AllowHeaders:     "Content-Type,Authorization",
		AllowCredentials: true,
	}))

	// Security headers
	app.Use(func(c *fiber.Ctx) error {
		c.Set("X-Frame-Options", "DENY")
		c.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'self'; script-src 'self'; object-src 'none';")
		c.Set("X-Content-Type-Options", "nosniff")
		c.Set("Referrer-Policy", "no-referrer")
		c.Set("Permissions-Policy", "camera=(), microphone=()")
		return c.Next()
	})

	// Base route group
	api := app.Group("/myapp")
	api.Get("/test", func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"status":  fiber.StatusOK,
			"message": "Success",
		})
	})

	usersRoute := api.Group("/users")

	usersRoute.Post("/add-user-details", userServer.AddUserDetails)
	api.Use(securityInit.AuthMiddleware)
	usersRoute.Post("/user-login", userServer.GetUserDetails)

	// Start server
	log.Printf("Server started on port %s\n", serverPort)
	log.Fatal(app.Listen(":" + serverPort))
}
