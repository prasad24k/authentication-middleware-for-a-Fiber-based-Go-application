package models

// DeviceInfo holds information about the user's device and location

type GenericResponseBody struct {
	Status  int         `json:"status"`
	Message string      `json:"message"`
	Error   string      `json:"error"`
	Data    interface{} `json:"data"`
}
type DeviceInfo struct {
	DeviceID     string `json:"deviceId"`
	DeviceSource string `json:"deviceSource"`
	DeviceType   string `json:"deviceType"`
	IPAddress    string `json:"ipAddress"`
	Latitude     string `json:"latitude"`
	Longitude    string `json:"longitude"`
	Country      string `json:"country"`
	Browser      string `json:"browser"`
}

// LoginRequest represents the structure for login request
type LoginRequest struct {
	MailID       string `json:"mailId"`
	UserPassword string `json:"userPassword"`
	DeviceInfo
}

// SignUpBody represents the structure for signup request
type SignUpBody struct {
	MailID       string `json:"mailId"`
	UserName     string `json:"userName"`
	UserPassword string `json:"userPassword"`
	DeviceInfo
}

// AuthResponse represents the structure for authentication responses
type AuthResponse struct {
	UserID      int    `json:"userId"`
	UserName    string `json:"userName"`
	AccessToken string `json:"accessToken"`
	IsNewUser   bool   `json:"isNewUser"`
}
