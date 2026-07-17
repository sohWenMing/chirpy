package envloader

import (
	"errors"
	"os"

	"github.com/joho/godotenv"
)

type EnvConfig struct {
	dbString string
	platform string
}

func (e *EnvConfig) GetDBString() string {
	return e.dbString
}
func (e *EnvConfig) GetPlatform() string {
	return e.platform
}

func LoadEnv(path string) (envConfig *EnvConfig, err error) {
	err = godotenv.Load(path)
	if err != nil {
		return nil, err
	}
	dbString := os.Getenv("DB_URL")
	if dbString == "" {
		return nil, errors.New("db string could not be found from environment variables. Check configuration.")
	}
	platform := os.Getenv("PLATFORM")
	if platform == "" {
		return nil, errors.New("platform could not be found from environment variables. Check configuration.")
	}
	envConfig = &EnvConfig{
		dbString: dbString,
		platform: platform,
	}
	return envConfig, nil
}
