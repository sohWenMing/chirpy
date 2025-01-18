package auth

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (hashedPassword string, err error) {
	passwordBytes := []byte(password)
	hashBytes, hashError := bcrypt.GenerateFromPassword(passwordBytes, 10)
	if hashError != nil {
		return "", err
	}
	return string(hashBytes), nil
}

func CheckPasswordHash(password, hash string) (err error) {
	passwordBytes := []byte(password)
	hashBytes := []byte(hash)
	hashErr := bcrypt.CompareHashAndPassword(hashBytes, passwordBytes)
	return hashErr
}

func MakeJWTWithClaims(uuid uuid.UUID, secret string, expirationTime time.Duration) (string, error) {
	expiration := time.Now().Add(expirationTime)
	uuidString := uuid.String()
	if uuidString == "" {
		return "", errors.New("uuid passed in could not be parsed to string")
	}
	claims := jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(expiration),
		Subject:   uuid.String(),
	}

	var signMethod jwt.SigningMethod = jwt.SigningMethodHS256

	token := jwt.NewWithClaims(signMethod, claims)
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func ValidateJWT(tokenString, secret string) (uuid.UUID, error) {
	claims := jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(tokenString, &claims, func(*jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil {
		return uuid.Nil, err
	}
	if !token.Valid {
		return uuid.Nil, err
	}
	if claims.ExpiresAt.Time.Before(time.Now()) {
		return uuid.Nil, errors.New("token has expired")
	}
	parseUUID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return uuid.Nil, err
	}
	return parseUUID, nil
}

func GetBearerToken(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("authorization header not defined")
	}
	tokenString, isFound := strings.CutPrefix(authHeader, "Bearer ")
	if !isFound {
		return "", errors.New("auth did not come with bearer prefix")
	}
	if tokenString == "" {
		return "", errors.New("tokenString evaluated to empty string")
	}
	return tokenString, nil

}
