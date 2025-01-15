package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/sohWenMing/chirpy/internal/database"
)

var profaneStringMap = map[string]bool{
	"kerfuffle": true,
	"sharbert":  true,
	"fornax":    true,
}

func main() {
	loadEnvErr := loadEnv()
	if loadEnvErr != nil {
		log.Fatal("error when loading environment, program exited")
	}

	platform := os.Getenv("PLATFORM")
	if platform == "" {
		log.Fatal("PLATFORM env var was not successfully loaded")
	}
	cfg := config{}
	cfg.platform = platform
	db := loadPostgresDB()
	cfg.registerQueries(database.New(db))
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/healthz", healthCheckHandler)
	mux.HandleFunc("GET /admin/metrics", cfg.metricsHandler)

	mux.HandleFunc("POST /api/validate_chirp", validateChirpHandler)
	mux.HandleFunc("POST /api/users", cfg.createUsersHandler)
	mux.HandleFunc("POST /admin/reset", cfg.resetUsersHandler)

	// mux.HandleFunc("/", baseHandler)

	fileServer := http.FileServer(http.Dir("."))
	wrappedFileServer := fsWrapper(fileServer)
	mux.Handle("/app/", http.StripPrefix("/app", cfg.middlewareMetricsInc(wrappedFileServer)))

	server := &http.Server{
		Handler: mux,
		Addr:    ":8080",
	}
	server.ListenAndServe()
}

func loadPostgresDB() *sql.DB {
	dbURL, dbURLErr := getDbUrl()
	if dbURLErr != nil {
		log.Fatalf("Error returned: %v", dbURLErr)
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("Error returned: %v", err)
	}
	return db
}

type config struct {
	fileServerHits atomic.Int32
	queries        *database.Queries
	platform       string
}

// handlers start
func validateChirpHandler(w http.ResponseWriter, r *http.Request) {

	type pararameters struct {
		Body string `json:"body"`
	}

	// body, _ := io.ReadAll(r.Body)
	// fmt.Printf("request body: %s\n", string(body))

	decoder := json.NewDecoder(r.Body)
	// decoder.DisallowUnknownFields()
	params := pararameters{}

	jsonDecodeErr := decoder.Decode(&params)

	if jsonDecodeErr != nil {
		writeErrToResponse(w, "Something went wrong during the decoding of the request body")
		return
	}
	fmt.Printf("value of body in params: %s\n", params.Body)

	if len(params.Body) > 140 {
		writeErrToResponse(w, "Chirp is too long")
		return
	}

	splitTrimmedStrings := getStrippedSplitStrings(params.Body)
	validatedStrings := []string{}
	for _, splitTrimmedString := range splitTrimmedStrings {
		if _, ok := profaneStringMap[strings.ToLower(splitTrimmedString)]; ok {
			validatedStrings = append(validatedStrings, "****")
			continue
		}
		validatedStrings = append(validatedStrings, splitTrimmedString)
	}

	writeValidToReponse(w, strings.Join(validatedStrings, " "))

}

func writeErrToResponse(w http.ResponseWriter, errorString string) {

	errorStruct := errorJsonStruct{
		ErrorString: errorString,
	}
	marshalledData, err := json.Marshal(errorStruct)

	if err != nil {
		log.Printf("error marshalling JSON: %s", err)
		w.WriteHeader(400)
		return
	}

	w.WriteHeader(400)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(marshalledData))

}

func (cfg *config) createUsersHandler(w http.ResponseWriter, r *http.Request) {

	type emailJsonStruct struct {
		Email string `json:"email"`
	}
	// bodyBytes, _ := io.ReadAll(r.Body)
	// fmt.Printf("bodyBytes: %s\n", bodyBytes)
	emailJson := emailJsonStruct{}

	decoder := json.NewDecoder(r.Body)
	decodeErr := decoder.Decode(&emailJson)
	if decodeErr != nil {
		writeErrToResponse(w, "bad request: payload could not be processed")
		return
	}
	if emailJson.Email == "" {
		writeErrToResponse(w, "bad request: email cannot be nil")
		return
	}

	user, createUserErr := createUser(emailJson.Email, cfg)
	if createUserErr != nil {
		writeErrToResponse(w, fmt.Sprintf("database error: %s", createUserErr.Error()))
		return
	}

	type createdUserStruct struct {
		ID        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Email     string    `json:"email"`
	}

	structToMarshal := createdUserStruct{
		ID:        user.ID,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		Email:     user.Email,
	}

	body, err := json.Marshal(structToMarshal)
	if err != nil {
		writeErrToResponse(w, "An error occured when marshalling the response")
		return
	}

	w.WriteHeader(201)
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)

}

func (cfg *config) resetUsersHandler(w http.ResponseWriter, _ *http.Request) {

	platform := cfg.platform
	if platform != "dev" {
		w.WriteHeader(403)
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("403 Forbidden"))
		return
	}

	resetErr := cfg.queries.DeleteUsers(context.Background())
	if resetErr != nil {
		writeErrToResponse(w, "Error when trying to reset users")
	}
	w.WriteHeader(200)
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("Users have been successfully reset"))

}

func createUser(email string, cfg *config) (user database.User, err error) {
	params := database.CreateUserParams{
		ID:        uuid.New(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Email:     email,
	}

	user, createUserErr := cfg.queries.CreateUser(context.Background(), params)
	if createUserErr != nil {
		return database.User{}, createUserErr
	}
	return user, nil

	// type CreateUserParams struct {
	// 	ID        uuid.UUID
	// 	CreatedAt time.Time
	// 	UpdatedAt time.Time
	// 	Email     string
	// }

}

func (cfg *config) metricsHandler(w http.ResponseWriter, _ *http.Request) {
	hits := cfg.fileServerHits.Load()
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	template := `
	<html>
  		<body>
    		<h1>Welcome, Chirpy Admin</h1>
    		<p>Chirpy has been visited %d times!</p>
  		</body>
	</html>
	`
	w.Write([]byte(fmt.Sprintf(template, hits)))
}

func (cfg *config) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		cfg.fileServerHits.Add(1)
		next.ServeHTTP(w, r)
	})

}

//handlers end

func getStrippedSplitStrings(input string) (outSlice []string) {
	fmt.Printf("string from input: %s\n", input)
	returnedSlice := []string{}
	splitStrings := strings.Split(input, " ")
	for _, splitString := range splitStrings {
		returnedSlice = append(returnedSlice, strings.Trim(splitString, " "))
	}
	for _, returnString := range returnedSlice {
		fmt.Printf("return string value: %s\n", returnString)
	}
	return returnedSlice
}

func writeValidToReponse(w http.ResponseWriter, responseString string) {
	type cleanedParams struct {
		CleanedBody string `json:"cleaned_body"`
	}

	resBodyStruct := cleanedParams{responseString}

	marshalledData, err := json.Marshal(resBodyStruct)
	if err != nil {
		log.Printf("error marshalling JSON: %s", err)
		w.WriteHeader(400)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(marshalledData))
}

func (cfg *config) registerQueries(queries *database.Queries) {
	cfg.queries = queries
}

// func baseHandler(w http.ResponseWriter, r *http.Request) {

// 	w.WriteHeader(http.StatusNotFound)
// 	w.Write([]byte("Placeholder for 404 not found"))
// }

func healthCheckHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
	w.Write([]byte("OK"))
}

func fsWrapper(fs http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			_, err := os.Stat("./index.html")
			if os.IsNotExist(err) {
				http.Error(w, "No index page found", 404)
				return
			}
		}
		fs.ServeHTTP(w, r)
	})
}

// type validStruct struct {
// 	ValidString bool `json:"valid"`
// }

type errorJsonStruct struct {
	ErrorString string `json:"error"`
}

func getDbUrl() (url string, err error) {
	db_url := os.Getenv("DB_URL")
	if len(db_url) == 0 {
		return "", errors.New("DB URL does not exist")
	}
	return db_url, nil
}

func loadEnv() error {
	loadErr := godotenv.Load()
	if loadErr != nil {
		return loadErr
	}
	return nil
}
