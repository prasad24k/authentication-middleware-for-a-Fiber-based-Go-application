package constants

import "errors"

const (
	ErrInvalidJSON           = "Invalid JSON body"
	ErrInternalDB            = "Internal database error"
	ErrSomethingWrong        = "Something went wrong"
	ErrMissingFields         = "Missing mandatory fields"
	ErrInvalidInputs         = "Invalid inputs"
	ErrUnauthorized          = "Invalid access"
	ErrFetchingToken         = "Could not fetch access token"
	ErrNoBookingUrlAvailable = "No booking urls found"
	Success                  = "Success"
)

var (
	ErrInvalidUUID  = errors.New("invalid UUID format")
	ErrUserNotFound = errors.New("user not found")
)

const (
	UserAlreadyExists  = "User already exists"
	UserNotFound       = "User does not exist"
	UserCreatedSuccess = "User created successfully"
)
