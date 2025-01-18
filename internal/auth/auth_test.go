package auth

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestHashPassword(t *testing.T) {
	testPassword := "Holoq123holoq123"
	_, err := HashPassword(testPassword)
	if err != nil {
		t.Error(err)
	}

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

func TestGetBearerToken(t *testing.T) {
	type testStruct struct {
		name               string
		token              string
		bearerString       string
		isErrExpected      bool
		isSetAuthorization bool
	}

	tests := []testStruct{

		{
			"passing test case",
			"Token123",
			"Bearer Token123",
			false,
			true,
		},
		{
			"failing test case no auth",
			"",
			"",
			true,
			false,
		},
		{
			"failing no bearer",
			"Token123",
			"Token123",
			true,
			true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet,
				"www.testURL.com", nil)
			if err != nil {
				t.Errorf("didn't expect error, got %v", err)
			}
			if test.isSetAuthorization {
				req.Header.Set("Authorization", test.bearerString)
			}
			_, getBearerErr := GetBearerToken(req.Header)
			switch test.isErrExpected {
			case true:
				if getBearerErr == nil {
					t.Errorf("expected error, didn't get one")
				}
			case false:
				if getBearerErr != nil {
					t.Errorf("didn't expect error, got %v", getBearerErr)
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
