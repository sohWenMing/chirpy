package auth

import "golang.org/x/crypto/bcrypt"

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
