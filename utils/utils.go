package utils

import (
	"authentication/models"

	"github.com/gofiber/fiber/v2"
)

func SendResponse(c *fiber.Ctx, status int, message string, errMessage string, data map[string]interface{}) error {
	response := models.GenericResponseBody{
		Status:  status,
		Message: message,
		Error:   errMessage,
	}

	if data == nil {
		response.Data = []interface{}{}
	} else {
		response.Data = data
	}

	return c.Status(fiber.StatusOK).JSON(response)
}
