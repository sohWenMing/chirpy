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
