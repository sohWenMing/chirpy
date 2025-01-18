package auth

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func TestHashPassword(t *testing.T) {
	testPassword := "Holoq123holoq123"
	hash, err := HashPassword(testPassword)
	if err != nil {
		t.Error(err)
	}
	fmt.Printf("hash result: %s", hash)
}

func TestCheckPasswordHash(t *testing.T) {
	type testStruct struct {
		name        string
		password    string
		hash        string
		isExpectErr bool
	}

	tests := []testStruct{
		{
			"test should pass",
			"Holoq123holoq123",
			"",
			false,
		},
		{
			"test should fail",
			"Holoq123holoq123",
			"",
			true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			hashedPassword, err := HashPassword(test.password)
			if err != nil {
				t.Error(err)
			}
			switch test.isExpectErr {
			case true:
				test.hash = "fail"
			case false:
				test.hash = hashedPassword
			}
			checkErr := CheckPasswordHash(test.password, test.hash)
			switch test.isExpectErr {
			case true:
				if checkErr == nil {
					t.Errorf("expected error, didn't get one")
				}
			case false:
				if checkErr != nil {
					t.Errorf("didn't expect error, got %v", checkErr)
				}
			}
		})
	}
}

func TestMakeJWTAndParse(t *testing.T) {
	uuid := uuid.New()
	tokenString := getTokenString(t, uuid, 3*time.Second, "this is my secret")
	claims := jwt.RegisteredClaims{}
	parser := jwt.NewParser()
	parser.ParseUnverified(tokenString, &claims)
	val := reflect.ValueOf(claims)
	for i := 0; i < val.NumField(); i++ {
		field := val.Type().Field(i)
		fieldValue := val.Field(i)
		fmt.Printf("%s: %v\n", field.Name, fieldValue)
	}
}

func TestParseTokenString(t *testing.T) {
	type testStruct struct {
		name               string
		tokenDuration      time.Duration
		secret             string
		isTestTamperSecret bool
		isErrExpected      bool
	}

	tests := []testStruct{
		{
			"test token should pass",
			3 * time.Second,
			"this is the secret",
			false,
			false,
		},
		{
			"test tamper secret",
			3 * time.Second,
			"this is the secret",
			true,
			false,
		},
		{
			"test token expired",
			0 * time.Second,
			"this is the secret",
			false,
			true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			uuid := uuid.New()
			tokenString := getTokenString(t, uuid, test.tokenDuration, test.secret)
			switch test.isErrExpected {
			case false:
				returnedUUID, err := ValidateJWT(tokenString, test.secret)
				if err != nil {
					t.Errorf("didn't expect error, got %v\n", err)
				}
				if uuid != returnedUUID {
					t.Errorf("got uuid: %v\nwant uuid: %v", returnedUUID, uuid)
				}
			case true:

				if test.isTestTamperSecret {
					test.secret = fmt.Sprintf("%s - add fail", test.secret)
				}
				_, err := ValidateJWT(tokenString, test.secret)
				if err == nil {
					t.Errorf("expected error, didn't get one")
				}

			}

		})
	}
}

func getTokenString(t *testing.T, uuid uuid.UUID, duration time.Duration, secret string) string {
	tokenString, err := MakeJWTWithClaims(uuid, secret, duration)
	if err != nil {
		t.Errorf("didn't expect error, got %v", err)
	}
	return tokenString
}
