package user

import (
	"authentication/constants"
	"authentication/db"
	"authentication/models"
	"authentication/security"
	"authentication/utils"
	"log"

	"github.com/gofiber/fiber/v2"
	"golang.org/x/crypto/bcrypt"
)

type Server struct {
	DB db.Database
}

func (s *Server) AddUserDetails(c *fiber.Ctx) error {
	var signUpRequest models.SignUpBody

	if err := c.BodyParser(&signUpRequest); err != nil {
		return utils.SendResponse(c, fiber.StatusBadRequest, constants.ErrInvalidJSON, "Failed to parse the request payload.", nil)
	}

	if signUpRequest.MailID == "" || signUpRequest.UserName == "" || signUpRequest.UserPassword == "" {
		return utils.SendResponse(c, fiber.StatusBadRequest, constants.ErrMissingFields, "MailID, UserName, or UserPassword is missing.", nil)
	}

	// Check if user already exists
	exists, err := s.DB.IsUserEmailExists(signUpRequest.MailID)
	if err != nil {
		return utils.SendResponse(c, fiber.StatusInternalServerError, constants.ErrInternalDB, "Failed to check user existence.", nil)
	}

	if exists {
		return utils.SendResponse(c, fiber.StatusConflict, constants.UserAlreadyExists, "User with this email already exists.", nil)
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(signUpRequest.UserPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Println("Error hashing password:", err)
		return utils.SendResponse(c, fiber.StatusInternalServerError, constants.ErrInternalDB, "Failed to hash password.", nil)
	}

	// Insert user
	userID, err := s.DB.InsertUserDetails(signUpRequest.MailID, signUpRequest.UserName, string(hashedPassword))
	if err != nil {
		return utils.SendResponse(c, fiber.StatusBadGateway, constants.ErrInternalDB, "Failed to insert user details.", nil)
	}

	// Generate JWT token
	accessToken, err := security.GenerateJWT(userID.String())
	if err != nil {
		log.Println("Error generating JWT:", err)
		return utils.SendResponse(c, fiber.StatusInternalServerError, constants.ErrSomethingWrong, "Failed to generate authentication token.", nil)
	}

	// Store token asynchronously
	go func() {
		err := s.DB.InsertUserToken(userID, accessToken)
		if err != nil {
			log.Println("Error inserting user token:", err)
		}
	}()

	return utils.SendResponse(c, fiber.StatusCreated, constants.Success, "User created successfully.", fiber.Map{
		"user_id":      userID,
		"user_name":    signUpRequest.UserName,
		"access_token": accessToken,
	})
}

func (s *Server) GetUserDetails(c *fiber.Ctx) error {
	var req models.LoginRequest
	var deviceInfo models.DeviceInfo

	if err := c.BodyParser(&req); err != nil {
		return utils.SendResponse(c, fiber.StatusBadRequest, constants.ErrInvalidJSON, "Invalid request body", nil)
	}
	c.BodyParser(&deviceInfo) // Ignore error as device info is optional

	if req.MailID == "" || req.UserPassword == "" {
		return utils.SendResponse(c, fiber.StatusBadRequest, constants.ErrMissingFields, "MailID or password is missing", nil)
	}

	// Get user credentials
	userID, userName, hashedPassword, err := s.DB.GetUserCredentials(req.MailID)
	if err != nil {
		return utils.SendResponse(c, fiber.StatusUnauthorized, constants.ErrUnauthorized, "Invalid email or user not found.", nil)
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(req.UserPassword)); err != nil {
		return utils.SendResponse(c, fiber.StatusUnauthorized, constants.ErrUnauthorized, "Invalid password.", nil)
	}

	// Generate JWT token
	accessToken, err := security.GenerateJWT(userID.String())
	if err != nil {
		log.Println("Error generating JWT:", err)
		return utils.SendResponse(c, fiber.StatusInternalServerError, constants.ErrSomethingWrong, "Failed to generate authentication token.", nil)
	}

	// Update user token and record login history asynchronously
	go func() {
		// Update user token
		err := s.DB.UpsertUserToken(userID, accessToken)
		if err != nil {
			log.Printf("Error updating user token: %v", err)
		}

		// Record login history if device info provided
		if deviceInfo.DeviceID != "" {
			err = s.DB.InsertUserLoginHistory(
				userID,
				deviceInfo.DeviceID,
				deviceInfo.DeviceSource,
				deviceInfo.DeviceType,
				deviceInfo.IPAddress,
				deviceInfo.Latitude,
				deviceInfo.Longitude,
				deviceInfo.Country,
				deviceInfo.Browser,
			)
			if err != nil {
				log.Printf("Error inserting user login history: %v", err)
			}
		}
	}()

	return utils.SendResponse(c, fiber.StatusOK, constants.Success, "Login successful.", fiber.Map{
		"user_id":      userID,
		"user_name":    userName,
		"access_token": accessToken,
	})
}
