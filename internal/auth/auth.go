package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func MakeRefreshToken() string {
	data := make([]byte, 32)
	rand.Read(data)
	return hex.EncodeToString(data)
}

func HashPassword(password string) (string, error) {
	hash, err := argon2id.CreateHash(password, argon2id.DefaultParams)
	if err != nil {
		return "", err
	}
	return hash, nil
}
func CompareHashAndPassword(password, hash string) (bool, error) {
	isMatch, err := argon2id.ComparePasswordAndHash(password, hash)
	if err != nil {
		return false, err
	}
	return isMatch, nil
}

func MakeJWT(userId uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	claims := jwt.RegisteredClaims{
		Issuer:    "chirpy-access",
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn).UTC()),
		Subject:   userId.String(),
	}
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedString, err := jwtToken.SignedString([]byte(tokenSecret))
	if err != nil {
		return "", err
	}
	return signedString, nil
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (any, error) {
		return []byte(tokenSecret), nil
	})
	if err != nil {
		return uuid.UUID{}, err
	}
	claimsSubject, err := token.Claims.GetSubject()
	if err != nil {
		return uuid.UUID{}, err
	}
	parsedUuid, err := uuid.Parse(claimsSubject)
	if err != nil {
		return uuid.UUID{}, err
	}
	return parsedUuid, nil
}

func GetBearerToken(header http.Header) (string, error) {
	pfx := "Bearer "
	authHeader := header.Get("Authorization")
	if !strings.HasPrefix(authHeader, pfx) {
		return "", errors.New(fmt.Sprintf("authorization header invalid. Value retrieved: %s\n", authHeader))
	}
	return strings.TrimSpace(strings.TrimPrefix(authHeader, pfx)), nil
}
