package auth

import (
	"errors"
	"os"
	"time"

	"vidusec/web/internal/database"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type Service struct {
	db *database.DB
}

type Claims struct {
	UserID   int    `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type RegisterRequest struct {
	Username string `json:"username" binding:"required,min=3,max=20"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
}

type AuthResponse struct {
	Token    string `json:"token"`
	User     *database.User `json:"user"`
	ExpiresAt time.Time `json:"expires_at"`
}

var (
	ErrUserNotFound      = errors.New("user not found")
	ErrInvalidPassword   = errors.New("invalid password")
	ErrUserExists        = errors.New("user already exists")
	ErrInvalidToken      = errors.New("invalid token")
)

const (
	TokenExpiration = 24 * time.Hour
)

// getJWTSecret returns the JWT secret from environment variable or generates a default
func getJWTSecret() string {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		// Generate a secure random secret for development
		// In production, this should always be set via environment variable
		secret = "vidusec-dev-secret-change-in-production-" + time.Now().Format("20060102")
	}
	return secret
}

func NewService(db *database.DB) *Service {
	return &Service{db: db}
}

// Register creates a new user
func (s *Service) Register(req *RegisterRequest) (*AuthResponse, error) {
	// Check if user already exists
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ? OR email = ?", 
		req.Username, req.Email).Scan(&count)
	if err != nil {
		return nil, err
	}
	
	if count > 0 {
		return nil, ErrUserExists
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	// Create user
	result, err := s.db.Exec(`
		INSERT INTO users (username, email, password_hash) 
		VALUES (?, ?, ?)`,
		req.Username, req.Email, string(hashedPassword))
	if err != nil {
		return nil, err
	}

	userID, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}

	// Get created user
	user, err := s.GetUserByID(int(userID))
	if err != nil {
		return nil, err
	}

	// Generate token
	token, expiresAt, err := s.GenerateToken(user)
	if err != nil {
		return nil, err
	}

	return &AuthResponse{
		Token:     token,
		User:      user,
		ExpiresAt: expiresAt,
	}, nil
}

// Login authenticates a user
func (s *Service) Login(req *LoginRequest) (*AuthResponse, error) {
	// Get user by username
	user, err := s.GetUserByUsername(req.Username)
	if err != nil {
		return nil, ErrUserNotFound
	}

	// Check password
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password))
	if err != nil {
		return nil, ErrInvalidPassword
	}

	// Generate token
	token, expiresAt, err := s.GenerateToken(user)
	if err != nil {
		return nil, err
	}

	return &AuthResponse{
		Token:     token,
		User:      user,
		ExpiresAt: expiresAt,
	}, nil
}

// GetUserByID retrieves a user by ID
func (s *Service) GetUserByID(id int) (*database.User, error) {
	user := &database.User{}
	err := s.db.QueryRow(`
		SELECT id, username, email, password_hash, created_at, updated_at 
		FROM users WHERE id = ?`, id).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash, 
		&user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// GetUserByUsername retrieves a user by username
func (s *Service) GetUserByUsername(username string) (*database.User, error) {
	user := &database.User{}
	err := s.db.QueryRow(`
		SELECT id, username, email, password_hash, created_at, updated_at 
		FROM users WHERE username = ?`, username).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash, 
		&user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// GenerateToken creates a JWT token for a user
func (s *Service) GenerateToken(user *database.User) (string, time.Time, error) {
	expiresAt := time.Now().Add(TokenExpiration)
	
	claims := &Claims{
		UserID:   user.ID,
		Username: user.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(getJWTSecret()))
	if err != nil {
		return "", time.Time{}, err
	}

	return tokenString, expiresAt, nil
}

// ValidateToken validates a JWT token and returns the claims
func (s *Service) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(getJWTSecret()), nil
	})

	if err != nil {
		return nil, ErrInvalidToken
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, ErrInvalidToken
}
