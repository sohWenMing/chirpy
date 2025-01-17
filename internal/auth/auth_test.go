package auth

import (
	"fmt"
	"testing"
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
