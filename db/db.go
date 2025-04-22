package db

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

type PgDB struct {
	Pool *pgxpool.Pool
}

type Database interface {
	Close() error

	// User management
	InsertUserDetails(mailID, userName, userPassword string) (uuid.UUID, error)
	GetUserCredentials(mailID string) (uuid.UUID, string, string, error)
	GetUserByCredentials(mailID string, inputPassword string) (uuid.UUID, string, error)
	IsUserIdExists(userId uuid.UUID) (bool, error)
	IsUserEmailExists(email string) (bool, error)

	// Token management
	GetUserToken(userID uuid.UUID) (string, error)
	InsertUserToken(userID uuid.UUID, token string) error
	UpsertUserToken(userID uuid.UUID, token string) error

	// Login history
	InsertUserLoginHistory(userID uuid.UUID, deviceID, deviceSource, deviceType, ipAddress, latitude, longitude, country, browser string) error
}

func ConnectDB() (Database, error) {
	errEnv := godotenv.Load()
	if errEnv != nil {
		log.Fatal("Error loading .env file")
	}
	ipR := os.Getenv("DB_IP")
	portR := os.Getenv("DB_PORT")
	dbNameR := os.Getenv("DB_NAME")
	userNameR := os.Getenv("DB_USER")
	passwordR := os.Getenv("DB_PASSWORD")

	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s pool_max_conns=821",
		ipR, portR, userNameR, passwordR, dbNameR)
	// log.Println("DB Connection String:", connStr)
	pool, err := pgxpool.New(context.Background(), connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to read database: %w", err)
	}
	return &PgDB{Pool: pool}, nil
}

func (db *PgDB) Close() error {
	if db.Pool == nil {
		return errors.New("database pool is not connected")
	}
	db.Pool.Close()
	return nil
}

func (db *PgDB) InsertUserDetails(mailID, userName, userPassword string) (uuid.UUID, error) {
	query := `
		INSERT INTO public.user_details_master (
			mail_id,
			user_name,
			user_password
		) VALUES ($1, $2, $3)
		RETURNING user_id
	`

	var userID uuid.UUID
	err := db.Pool.QueryRow(context.Background(), query, mailID, userName, userPassword).Scan(&userID)
	if err != nil {
		log.Println("Error inserting user details:", err)
		return uuid.Nil, err
	}

	return userID, nil
}

func (db *PgDB) GetUserCredentials(mailID string) (uuid.UUID, string, string, error) {
	log.Printf("Attempting to fetch credentials for email: %s", mailID)

	query := `
        SELECT user_id, user_name, user_password
        FROM public.user_details_master
        WHERE mail_id = $1
    `
	var userID uuid.UUID
	var userName, hashedPassword string

	err := db.Pool.QueryRow(context.Background(), query, mailID).Scan(&userID, &userName, &hashedPassword)
	if err != nil {
		log.Printf("Error fetching user credentials: %v", err)
		return uuid.Nil, "", "", err
	}

	log.Printf("Successfully fetched credentials for user: %s (ID: %s)", userName, userID)
	return userID, userName, hashedPassword, nil
}
func (db *PgDB) GetUserByCredentials(mailID string, inputPassword string) (uuid.UUID, string, error) {
	query := `
		SELECT user_id, user_name, user_password
		FROM public.user_details_master
		WHERE mail_id = $1
	`
	var userID uuid.UUID
	var userName, hashedPassword string
	err := db.Pool.QueryRow(context.Background(), query, mailID).Scan(&userID, &userName, &hashedPassword)
	if err != nil {
		log.Println("Error fetching user:", err)
		return uuid.Nil, "", err
	}

	// Compare hashed password
	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(inputPassword)); err != nil {
		log.Println("Password mismatch:", err)
		return uuid.Nil, "", fmt.Errorf("invalid credentials")
	}

	return userID, userName, nil
}

func (db *PgDB) IsUserIdExists(userId uuid.UUID) (bool, error) {
	log.Printf("Checking if user exists: %s", userId)

	query := `SELECT 1 FROM user_details_master WHERE user_id = $1`

	var exists int
	err := db.Pool.QueryRow(context.Background(), query, userId).Scan(&exists)
	if err != nil {
		if err == pgx.ErrNoRows {
			log.Printf("User %s not found", userId)
			return false, nil
		}
		log.Printf("Database error checking user existence: %v", err)
		return false, fmt.Errorf("error checking user ID existence: %v", err)
	}

	log.Printf("User %s exists", userId)
	return true, nil
}

func (db *PgDB) GetUserToken(userID uuid.UUID) (string, error) {
	var accessToken string
	query := `SELECT access_token FROM public.user_jwt_auth WHERE user_id = $1`

	err := db.Pool.QueryRow(context.Background(), query, userID).Scan(&accessToken)
	if err != nil {
		if err == pgx.ErrNoRows {
			log.Println("No token found for user_id:", userID)
			return "", nil
		}
		log.Println("Error fetching user token:", err)
		return "", err
	}
	return accessToken, nil
}

func (db *PgDB) IsUserEmailExists(email string) (bool, error) {
	query := `SELECT 1 FROM user_details_master WHERE mail_id = $1`

	var exists int
	err := db.Pool.QueryRow(context.Background(), query, email).Scan(&exists)
	if err != nil {
		if err == pgx.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("error checking email existence: %v", err)
	}

	return true, nil
}

func (db *PgDB) InsertUserToken(userID uuid.UUID, token string) error {
	query := `
		INSERT INTO public.user_jwt_auth (
			user_id,
			access_token,
			created_at
		) VALUES ($1, $2, $3)
	`

	_, err := db.Pool.Exec(context.Background(), query, userID, token, time.Now())
	if err != nil {
		log.Println("Error inserting user token:", err)
		return err
	}

	return nil
}

func (db *PgDB) UpsertUserToken(userID uuid.UUID, token string) error {
	query := `
		INSERT INTO public.user_jwt_auth (
			user_id,
			access_token,
			created_at
		) VALUES ($1, $2, $3)
		ON CONFLICT (user_id) DO UPDATE
		SET access_token = $2,
			updated_at = $3
	`

	_, err := db.Pool.Exec(context.Background(), query, userID, token, time.Now())
	if err != nil {
		log.Println("Error upserting user token:", err)
		return err
	}

	return nil
}

func (db *PgDB) InsertUserLoginHistory(userID uuid.UUID, deviceID, deviceSource, deviceType, ipAddress, latitude, longitude, country, browser string) error {
	query := `
		INSERT INTO public.user_login_history (
			user_id,
			device_id,
			device_source,
			device_type,
			ip_address,
			latitude,
			longitude,
			country,
			browser,
			login_time
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`

	_, err := db.Pool.Exec(
		context.Background(),
		query,
		userID,
		deviceID,
		deviceSource,
		deviceType,
		ipAddress,
		latitude,
		longitude,
		country,
		browser,
		time.Now(),
	)

	if err != nil {
		log.Println("Error inserting user login history:", err)
		return err
	}

	return nil
}
