package modelprocessing

import (
	"database/sql"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/sohWenMing/chirpy/internal/database"
)

type reprUser struct {
	Id        uuid.NullUUID `json:"id"`
	CreatedAt sql.NullTime  `json:"created_at"`
	UpdatedAt sql.NullTime  `json:"updated_at"`
	Email     string        `json:"email"`
}

func RepresentUserRetrievedByEmail(u database.User) (returned []byte, err error) {
	reprUser := reprUser{
		uuid.NullUUID{UUID: u.ID, Valid: true}, u.CreatedAt, u.UpdatedAt, u.Email,
	}
	bytes, err := json.Marshal(reprUser)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// gets a byte slice of the json representation of the user.
// All data members will be lowercased
func RepresentUser(u database.User) (returned []byte, err error) {
	reprUser := reprUser{
		uuid.NullUUID{UUID: u.ID, Valid: true}, u.CreatedAt, u.UpdatedAt, u.Email,
	}
	bytes, err := json.Marshal(reprUser)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

type ReprChirp struct {
	Id        uuid.NullUUID `json:"id"`
	CreatedAt sql.NullTime  `json:"created_at"`
	UpdatedAt sql.NullTime  `json:"updated_at"`
	Body      string        `json:"body"`
	UserId    uuid.NullUUID `json:"user_id"`
}

func RepresentChirp(c database.Chirp) (returned []byte, err error) {
	reprChirp := ReprChirp{
		Id:        uuid.NullUUID{UUID: c.ID, Valid: true},
		CreatedAt: c.CreatedAt,
		UpdatedAt: c.UpdatedAt,
		Body:      c.Body,
		UserId:    uuid.NullUUID{UUID: c.UserID, Valid: true},
	}
	bytes, err := json.Marshal(reprChirp)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

func MapDBChirpToReprChirp(c database.Chirp) (returnedChirp ReprChirp) {
	return ReprChirp{
		Id:        uuid.NullUUID{UUID: c.ID, Valid: true},
		CreatedAt: c.CreatedAt,
		UpdatedAt: c.UpdatedAt,
		Body:      c.Body,
		UserId:    uuid.NullUUID{UUID: c.UserID, Valid: true},
	}
}
