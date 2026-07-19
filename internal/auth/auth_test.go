package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCreateRefreshToken(t *testing.T) {
	refreshToken := MakeRefreshToken()
	if len(refreshToken) == 0 {
		t.Errorf("refresh token should not be empty")
		return
	}
}

func TestPasswordHashing(t *testing.T) {
	type test struct {
		name            string
		password        string
		checkedHash     string
		isCheckNotMatch bool
	}

	tests := []test{
		{
			"test that valid will pass",
			"p@ssword",
			"",
			false,
		},
		{
			"test that invalid will pass",
			"p@ssword",
			"",
			true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := HashPassword(test.password)
			if err != nil {
				t.Errorf("didn't expect error, got %v\n", err)
				return
			}
			test.checkedHash = got
			if test.isCheckNotMatch {
				// we need a valid hash still, so to test we change the password
				test.password = "change_password"
			}
			isMatch, err := CompareHashAndPassword(test.password, test.checkedHash)
			if err != nil {
				t.Errorf("didn't expect error in check hash. Got %v\n", err)
				return
			}
			switch test.isCheckNotMatch {
			case true:
				if isMatch {
					t.Errorf("invalid password and hash should not match")
					return
				}
			default:
				if !isMatch {
					t.Errorf("valid hash and password should match")
					return
				}
			}
		})
	}
}

func TestJWTFunctionality(t *testing.T) {
	type test struct {
		name       string
		secret     string
		isTestPass bool
	}
	tests := []test{
		{
			"basic should pass",
			"thisIsASecret",
			true,
		},
		{
			"basic should pass",
			"thisIsASecret",
			false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			uuid, _ := uuid.NewRandom()

			jwt, err := MakeJWT(uuid, test.secret, 5*time.Minute)
			if err != nil {
				t.Errorf("didn't expect error, got %v\n", err)
				return
			}
			if test.isTestPass {
				returnedUUID, err := ValidateJWT(jwt, test.secret)
				if err != nil {
					t.Errorf("didn't expect error, got %v\n", err)
					return
				}
				got := returnedUUID.String()
				want := uuid.String()

				if got != want {
					t.Errorf("got %s\nwant %s\n", got, want)
					return
				}
			} else {
				wrongSecret := test.secret + "some_stuff"
				_, err := ValidateJWT(jwt, wrongSecret)
				if err == nil {
					t.Errorf("expected error, didn't get one ")
					return
				}
			}
		})
	}
}
