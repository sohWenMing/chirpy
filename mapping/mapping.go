package mapping

import (
	"time"

	"github.com/google/uuid"
	"github.com/sohWenMing/chirpy/internal/database"
)

type ChirpJSONMap struct {
	Id        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

type UserInfoWithTokensJSONMap struct {
	Id           uuid.UUID `json:"id"`
	Created_at   time.Time `json:"created_at"`
	Updated_at   time.Time `json:"updated_at"`
	Email        string    `json:"email"`
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
	IsChirpyRed  bool      `json:"is_chirpy_red"`
}

type UserInfoJSONMap struct {
	Id           uuid.UUID `json:"id"`
	Created_at   time.Time `json:"created_at"`
	Updated_at   time.Time `json:"updated_at"`
	Email        string    `json:"email"`
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
	IsChirpyRed  bool      `json:"is_chirpy_red"`
}

func MapDBChirpToChirpJSONMapping(dbChirp database.Chirp) ChirpJSONMap {
	return ChirpJSONMap{
		Id:        dbChirp.ID,
		CreatedAt: dbChirp.CreatedAt,
		UpdatedAt: dbChirp.UpdatedAt,
		Body:      dbChirp.Body,
		UserID:    dbChirp.UserID,
	}
}

func MapDBChirpsToChirpJSONMappings(dbChirps []database.Chirp) (chirpJSONMaps []ChirpJSONMap) {
	returnedJSONMaps := []ChirpJSONMap{}
	for _, dbChirp := range dbChirps {
		chirpJSONMap := MapDBChirpToChirpJSONMapping(dbChirp)
		returnedJSONMaps = append(returnedJSONMaps, chirpJSONMap)
	}
	return returnedJSONMaps
}

func MapUserInfoWithTokensJSONMap(user database.User, tokenString, refreshTokenString string) UserInfoWithTokensJSONMap {
	mappedJSON := UserInfoWithTokensJSONMap{
		Id:           user.ID,
		Created_at:   user.CreatedAt,
		Updated_at:   user.UpdatedAt,
		Email:        user.Email,
		Token:        tokenString,
		RefreshToken: refreshTokenString,
		IsChirpyRed:  user.IsChirpyRed.Bool,
	}
	return mappedJSON
}

func MapUserInfoJSONMap(user database.User) UserInfoJSONMap {
	mappedJSON := UserInfoJSONMap{
		Id:          user.ID,
		Created_at:  user.CreatedAt,
		Updated_at:  user.UpdatedAt,
		Email:       user.Email,
		IsChirpyRed: user.IsChirpyRed.Bool,
	}
	return mappedJSON
}
