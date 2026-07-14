package databaseconnection

import (
	"database/sql"

	_ "github.com/lib/pq"
	"github.com/sohWenMing/chirpy/envloader"
	"github.com/sohWenMing/chirpy/internal/database"
)

type DBToQueries struct {
	DB      *sql.DB
	Queries *database.Queries
}

func Connect(envPath string) (dbToQueries *DBToQueries, err error) {
	envConfig, err := envloader.LoadEnv(envPath)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("postgres", envConfig.GetDBString())
	if err != nil {
		return nil, err
	}
	return &DBToQueries{
		DB:      db,
		Queries: database.New(db),
	}, nil
}
