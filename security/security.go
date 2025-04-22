package security

import (
	"authentication/constants"
	"authentication/db"
	"authentication/utils"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

type Server struct {
	RedisClient *redis.Client
	DB          db.Database
}

func GetJWTSecretKey() ([]byte, error) {
	secretString := os.Getenv("JWT_SECRET")
	if secretString == "" {
		log.Println("JWT_SECRET is not set.")
		return nil, fmt.Errorf("JWT_SECRET is not set in the .env files")
	}
	return []byte(secretString), nil
}

var JwtSecretKey = []byte("sdcfvgrbhntjymhtbgrfvdcsx")

func GenerateJWT(signerKey string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userId": signerKey,
		"exp":    time.Now().Add(60 * time.Minute).Unix(), // Access token expires in 10 minutes
	})
	secret, _ := GetJWTSecretKey()
	accessToken, err := token.SignedString(secret)
	if err != nil {
		return "", fmt.Errorf("failed to sign access token: %w", err)
	}

	return accessToken, nil
}

func (s *Server) AuthMiddleware(c *fiber.Ctx) error {
	log.Println("Middleware HIT!!!!")
	secret, _ := GetJWTSecretKey()

	// Extract the Authorization header
	authHeader := c.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		return utils.SendResponse(c, fiber.StatusUnauthorized, constants.ErrUnauthorized, "Missing or invalid Authorization header", nil)
	}
	accessToken := strings.TrimPrefix(authHeader, "Bearer ")
	if accessToken != "" {
		claims := jwt.MapClaims{}
		_, err := jwt.ParseWithClaims(accessToken, claims, func(token *jwt.Token) (interface{}, error) {
			return secret, nil
		})
		if err == nil && claims["exp"].(float64) > float64(time.Now().Unix()) {
			// Fetch the userId from the JWT token
			tokenUserId := claims["userId"].(string)
			var payload struct {
				UserId int `json:"userId"`
			}

			var userId string
			fullPath := c.Path()
			log.Println("Full Path: ", fullPath)

			// Split the URL path into parts
			pathParts := strings.Split(fullPath, "/")
			log.Println("Path Parts: ", pathParts)

			// Get the last element of the path (which would be your userId)
			userId = pathParts[len(pathParts)-1]
			log.Println("UserId from end of URL: ", userId)

			// Step 2: Validate if userId from URL is a valid integer
			if userId != "" {
				if _, err := strconv.Atoi(userId); err == nil {
					// If the userId is a valid integer, use it
					log.Println("Valid UserId from path:", userId)
				} else {
					// If not a valid integer, move to the next check
					log.Println("Invalid UserId from path, checking other sources")
					userId = ""
				}
			}

			// Step 3: Fetch userId from request body (if needed)
			if userId == "" {
				if err := c.BodyParser(&payload); err == nil && payload.UserId != 0 {
					userId = fmt.Sprintf("%d", payload.UserId)
					log.Println("UserId from body:", userId)
				}
			}

			// Step 4: If still no userId, fetch from query parameters
			if userId == "" {
				userId = c.Query("userId")
				log.Println("UserId from query:", userId)
			}

			// Step 5: If still no userId, log a warning or handle the error
			if userId == "" {
				log.Println("UserId not found in any source.")
			}
			// Check if userid is passed in URL or request body

			// Logged userId for debugging
			log.Printf("UserID from token: %s, UserID from request: %s", tokenUserId, userId)

			// Checking if userId is matching or not with payload
			var cond = userId != "" && tokenUserId != userId
			if cond {
				log.Println("UserId Check Condition: ", cond)
				return utils.SendResponse(c, fiber.StatusUnauthorized, constants.ErrUnauthorized, "UserId mismatched", nil)
			}

			// Convert tokenUserId to UUID
			tokenUserIdUUID, err := uuid.Parse(tokenUserId)
			if err != nil {
				return utils.SendResponse(c, fiber.StatusBadRequest, constants.ErrInvalidJSON, "Invalid user ID format", nil)
			}

			// Fetching from DB whether user exists
			isExists, err := s.DB.IsUserIdExists(tokenUserIdUUID)
			if err != nil {
				return utils.SendResponse(c, fiber.StatusBadGateway, constants.ErrInternalDB, "Failed to check user Id exists.", nil)
			}

			if isExists {
				c.Locals("agentUserId", claims["userId"].(string))
				storedToken, err := s.DB.GetUserToken(tokenUserIdUUID)
				if err != nil {
					return utils.SendResponse(c, fiber.StatusBadGateway, constants.ErrInternalDB, "Failed to fetch user tokens.", nil)
				}
				if storedToken == accessToken {
					log.Println("Tokens are valid")
					return c.Next()
				}
				return utils.SendResponse(c, fiber.StatusUnauthorized, constants.ErrUnauthorized, "Token mismatch.", nil)
			}
			return utils.SendResponse(c, fiber.StatusUnauthorized, constants.ErrUnauthorized, "User does not exist.", nil)
		}
		return utils.SendResponse(c, fiber.StatusUnauthorized, constants.ErrUnauthorized, "Token is expired.", nil)
	}
	return utils.SendResponse(c, fiber.StatusUnauthorized, constants.ErrUnauthorized, "No access token found.", nil)
}
