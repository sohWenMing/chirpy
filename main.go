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
	"github.com/sohWenMing/chirpy/internal/auth"
	"github.com/sohWenMing/chirpy/internal/database"
	"github.com/sohWenMing/chirpy/mapping"
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

	secret := os.Getenv("SECRET")
	if secret == "" {
		log.Fatal("SECRET env var was not successfully loaded")
	}
	cfg := config{}
	cfg.platform = platform
	cfg.secret = secret
	db := loadPostgresDB()
	cfg.registerQueries(database.New(db))
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/healthz", healthCheckHandler)
	mux.HandleFunc("GET /admin/metrics", cfg.metricsHandler)

	mux.HandleFunc("POST /api/chirps", cfg.validateChirpHandler)
	mux.HandleFunc("POST /api/users", cfg.createUsersHandler)
	mux.HandleFunc("PUT /api/users", cfg.updateUserInfoHandler)
	mux.HandleFunc("POST /api/login", cfg.loginUserHandler)
	mux.HandleFunc("POST /api/refresh", cfg.refreshTokenHandler)
	mux.HandleFunc("POST /api/revoke", cfg.revokeRefreshTokenHandler)
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", cfg.deleteChirpHandler)
	mux.HandleFunc("POST /admin/reset", cfg.resetUsersHandler)
	mux.HandleFunc("GET /api/chirps", cfg.getChirpsHandler)
	mux.HandleFunc("GET /api/chirps/{chirpID}", cfg.getChirpByIdHandler)
	mux.HandleFunc("POST /api/polka/webhooks", cfg.setIsUserChirpRedHandler)
	fileServer := http.FileServer(http.Dir("."))
	wrappedFileServer := fsWrapper(fileServer)
	mux.Handle("/app/", http.StripPrefix("/app", cfg.middlewareMetricsInc(wrappedFileServer)))

	server := &http.Server{
		Handler: mux,
		Addr:    ":8080",
	}
	if err := server.ListenAndServe(); err != nil {
		log.Fatal("Server failed to start:", err)
	}
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
	secret         string
}

// handlers start
func (cfg *config) loginUserHandler(w http.ResponseWriter, r *http.Request) {

	//decode payload from request
	type loginPayloadStruct struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	payload := loginPayloadStruct{}

	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&payload)

	if err != nil {
		writeErrToResponse(w, "bad request")
	}

	//check that user exists in database
	user, err := cfg.queries.GetUserByEmail(context.Background(), payload.Email)

	shouldReturnEarly := checkDBErrAndWriteErr(err, w, "user with email could not be found")
	if shouldReturnEarly {
		return
	}

	//verify password against hash in database
	isHashCheckErr := auth.CheckPasswordHash(payload.Password, user.HashedPassword.String)
	if isHashCheckErr != nil {
		w.WriteHeader(401)
		w.Header().Set("content-type", "text-plain")
		w.Write([]byte("Incorrect email or password"))
		return
	}

	//create JTW Token
	tokenString, err := auth.MakeJWTWithClaims(user.ID, cfg.secret)
	if err != nil {
		writeErrToResponse(w, err.Error())
	}

	//generate data from refresh token
	returnedDBRefreshToken, err := makeNewRefreshToken(w, cfg, user.ID)
	if err != nil {
		return
	}
	//return response

	returnPayload := mapping.MapUserInfoWithTokensJSONMap(user, tokenString, returnedDBRefreshToken.ID)
	resBytes, jsonMarshaErr := json.Marshal(returnPayload)
	if jsonMarshaErr != nil {
		writeErrToResponse(w, "there was a problem logging in the user")
	}
	w.WriteHeader(200)
	w.Header().Set("content-type", "application/json")
	w.Write(resBytes)

}
func (cfg *config) setIsUserChirpRedHandler(w http.ResponseWriter, r *http.Request) {
	apiKey, err := auth.GetAPIKey(r)
	if err != nil || apiKey != os.Getenv("POLKA_KEY") {
		w.WriteHeader(401)
		return
	}
	type reqBody struct {
		Event string `json:"event"`
		Data  struct {
			UserID string `json:"user_id"`
		}
	}
	data := reqBody{}
	decoder := json.NewDecoder(r.Body)
	jsonDecodeErr := decoder.Decode(&data)
	if jsonDecodeErr != nil {
		writeErrToResponse(w, "error decoding payload body")
		return
	}
	if data.Event != "user.upgraded" {
		w.WriteHeader(204)
		return
	}
	uuid, parseErr := uuid.Parse(data.Data.UserID)
	if parseErr != nil {
		writeErrToResponse(w, "used Id is invalid")
	}

	dbErr := cfg.queries.UpgradeUser(context.Background(), uuid)
	if dbErr != nil {
		w.WriteHeader(404)
		w.Write([]byte("user not found"))
		return
	}
	w.WriteHeader(204)
}
func (cfg *config) refreshTokenHandler(w http.ResponseWriter, r *http.Request) {

	//get refreshToken from request, strip out bearer
	refreshTokenString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		write401Error(w)
		return
	}

	refreshTokenInfo, err := cfg.queries.GetRefreshTokenById(context.Background(), refreshTokenString)
	//if there was database error, means token info could no be retrieved. return 401
	if err != nil {
		write401Error(w)
		return
	}
	//return 401 if expired
	if refreshTokenInfo.ExpiresAt.Before(time.Now()) {
		write401Error(w)
		return
	}

	if refreshTokenInfo.RevokedAt.Valid {
		write401Error(w)
		return
	}

	//attempt to make new access token, if error, return 500
	newAccessToken, err := auth.MakeJWTWithClaims(refreshTokenInfo.UserID, cfg.secret)
	if err != nil {
		w.WriteHeader(500)
		w.Header().Set("content-type", "text/plain")
		w.Write([]byte("Internal Error"))
		return
	}

	type tokenReturnStruct struct {
		Token string `json:"token"`
	}

	resPayload := tokenReturnStruct{Token: newAccessToken}
	resBytes, marshalErr := json.Marshal(resPayload)
	if marshalErr != nil {
		w.WriteHeader(500)
		w.Header().Set("content-type", "text/plain")
		w.Write([]byte("Internal Error"))
		return
	}
	w.WriteHeader(200)
	w.Header().Set("content-type", "application/json")
	w.Write(resBytes)

}

func (cfg *config) updateUserInfoHandler(w http.ResponseWriter, r *http.Request) {
	//first check the the authorization
	authToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		write401Error(w)
		return
	}

	//validate JWT token, if vaidated will return the correct UserId
	userUuid, err := auth.ValidateJWT(authToken, cfg.secret)
	if err != nil {
		write401Error(w)
		return
	}
	//decode payload
	type payloadStruct struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}

	payload := payloadStruct{}

	decoder := json.NewDecoder(r.Body)
	jsonDecodeErr := decoder.Decode(&payload)

	if jsonDecodeErr != nil {
		writeErrToResponse(w, "bad request")
		return
	}

	//hash hew password
	hashedPW, err := auth.HashPassword(payload.Password)
	if err != nil {
		writeErrToResponse(w, "there was a problem with the request")
		return
	}

	//update new user information in user table
	params := database.UpdateUserParams{
		Email: payload.Email,
		HashedPassword: sql.NullString{
			String: hashedPW,
			Valid:  true},
		ID:        userUuid,
		UpdatedAt: time.Now(),
	}
	newUserInfo, err := cfg.queries.UpdateUser(context.Background(), params)
	if err != nil {
		w.Header().Set("content-type", "text/plain")
		w.WriteHeader(500)
		w.Write([]byte("internal database error"))
		return
	}

	resbytes, jsonMappingErr := json.Marshal(mapping.MapUserInfoJSONMap(newUserInfo))
	if jsonMappingErr != nil {
		writeErrToResponse(w, "there was a problem with the request")
		return
	}
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(200)
	w.Write(resbytes)

}

func (cfg *config) revokeRefreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		writeErrToResponse(w, "token not found")
		return
	}

	params := database.RevokeRefreshTokenParams{
		ID:        refreshToken,
		UpdatedAt: time.Now(),
		RevokedAt: sql.NullTime{
			Time:  time.Now(),
			Valid: true,
		},
	}
	revokeErr := cfg.queries.RevokeRefreshToken(context.Background(), params)
	if revokeErr != nil {
		w.Header().Set("content-type", "text/plain")
		w.WriteHeader(500)
		w.Write([]byte("error when revoking token"))
		return
	}
	w.WriteHeader(204)
}

func (cfg *config) validateChirpHandler(w http.ResponseWriter, r *http.Request) {

	type pararameters struct {
		Body   string `json:"body"`
		UserID string `json:"user_id"`
	}

	decoder := json.NewDecoder(r.Body)

	params := pararameters{}

	jsonDecodeErr := decoder.Decode(&params)

	if jsonDecodeErr != nil {
		writeErrToResponse(w, "Something went wrong during the decoding of the request body")
		return
	}

	userUuid, shouldReturn := validateJWT(r, w, cfg)
	if shouldReturn {
		return
	}

	// _, getUserErr := cfg.queries.GetUserByUUID(context.Background(), userUuid)
	// if getUserErr != nil {
	// 	write401Error(w)
	// }

	isChirpLengthValid := validateChirpLength(params.Body)
	if isChirpLengthValid {
		writeErrToResponse(w, "Chirp length is too long")
		return
	}

	validatedBody := getValidatedChirpBody(params.Body)

	createChirpParams := database.CreateChirpParams{
		ID:        uuid.New(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Body:      validatedBody,
		UserID:    userUuid,
	}

	chirp, err := cfg.queries.CreateChirp(context.Background(), createChirpParams)
	if err != nil {
		writeErrToResponse(w, "error occured on creating chirp")
		return
	}

	createdChirpJson := mapping.MapDBChirpToChirpJSONMapping(chirp)

	resBytes, err := json.Marshal(createdChirpJson)
	if err != nil {
		writeErrToResponse(w, "error occured on marshalling response")
	}

	w.WriteHeader(201)
	w.Header().Set("content-type", "application/json")
	w.Write(resBytes)
}

func (cfg *config) deleteChirpHandler(w http.ResponseWriter, r *http.Request) {
	//first thing, get the chirpId from the path value
	chirpId := r.PathValue("chirpID")
	userUuid, shouldReturn := validateJWT(r, w, cfg)
	if shouldReturn {
		return
	}
	chirpIdUUID, err := uuid.Parse(chirpId)
	if err != nil {
		writeErrToResponse(w, "chirp Id passed in parameters wasn't valid")
		return
	}

	chirpToDelete, err := cfg.queries.GetChirpById(context.Background(), chirpIdUUID)
	if err != nil {
		w.Header().Set("content-type", "text/plain")
		w.WriteHeader(404)
		w.Write([]byte("chirp with id was not found"))
		return
	}
	if userUuid != chirpToDelete.UserID {
		w.Header().Set("content-type", "text/plain")
		w.WriteHeader(403)
		w.Write([]byte("403 Forbidden"))
		return
	}
	deleteErr := cfg.queries.DeleteChirpById(context.Background(), chirpToDelete.ID)
	if deleteErr != nil {
		w.Header().Set("content-type", "text/plain")
		w.WriteHeader(500)
		w.Write([]byte("database error"))
		return
	}
	w.WriteHeader(204)
}

func (cfg *config) getChirpsHandler(w http.ResponseWriter, r *http.Request) {
	authorId := r.URL.Query().Get("author_id")
	switch authorId == "" {
	case true:
		chirps, err := cfg.queries.GetChirps(context.Background())
		if err != nil {
			w.WriteHeader(500)
			w.Header().Set("content-type", "text/html; charset=UTF-8")
			w.Write([]byte("Internal database error"))
			return
		}
		mappedChirps := mapping.MapDBChirpsToChirpJSONMappings(chirps)
		resBytes, err := json.Marshal(mappedChirps)
		if err != nil {
			writeErrToResponse(w, "error occured on marshalling response")
			return
		}
		w.WriteHeader(200)
		w.Header().Set("content-type", "application/json")
		w.Write(resBytes)
		return
	case false:
		authorIdUuid, err := uuid.Parse(authorId)
		if err != nil {
			writeErrToResponse(w, "authorId could not be parsed")
			return
		}
		chirps, err := cfg.queries.GetChirpsByAuthorId(context.Background(), authorIdUuid)
		if err != nil {
			w.WriteHeader(500)
			w.Header().Set("content-type", "text/html; charset=UTF-8")
			w.Write([]byte("Internal database error"))
			return
		}

		mappedChirps := mapping.MapDBChirpsToChirpJSONMappings(chirps)
		resBytes, err := json.Marshal(mappedChirps)
		if err != nil {
			writeErrToResponse(w, "error occured on marshalling response")
			return
		}
		w.WriteHeader(200)
		w.Header().Set("content-type", "application/json")
		w.Write(resBytes)
		return
	}

}

func (cfg *config) getChirpByIdHandler(w http.ResponseWriter, r *http.Request) {
	chirpIdString := r.PathValue("chirpID")
	chirpUUID, err := uuid.Parse(chirpIdString)
	if err != nil {
		writeErrToResponse(w, fmt.Sprintf("chirpId %s could not be parsed to a proper chirpId", chirpIdString))
		return
	}
	chirp, err := cfg.queries.GetChirpById(context.Background(), chirpUUID)
	shouldReturnEarly := checkDBErrAndWriteErr(err, w, fmt.Sprintf("chirp with Id %s could not be found", chirpIdString))
	if shouldReturnEarly {
		return
	}
	jsonResponse := mapping.MapDBChirpToChirpJSONMapping(chirp)

	resBytes, marshalErr := json.Marshal(jsonResponse)
	if marshalErr != nil {
		writeErrToResponse(w, "There was a problem with the operation. Please try again later.")
	}
	w.WriteHeader(200)
	w.Header().Set("content-type", "application/json")
	w.Write(resBytes)
}

func makeNewRefreshToken(w http.ResponseWriter, cfg *config, userId uuid.UUID) (token database.RefreshToken, err error) {
	nullToken := database.RefreshToken{}
	refreshTokenString, err := auth.MakeRefreshToken()
	if err != nil {
		writeErrToResponse(w, err.Error())
		return nullToken, err
	}

	//store refresh token in DB
	returnedDBRefreshToken, err := cfg.queries.CreateRefreshToken(context.Background(), mapCreateRefreshTokenParams(refreshTokenString, userId))

	if err != nil {
		writeErrToResponse(w, err.Error())
		return nullToken, err
	}
	return returnedDBRefreshToken, nil
}

func mapCreateRefreshTokenParams(refreshTokenString string, userId uuid.UUID) database.CreateRefreshTokenParams {
	return database.CreateRefreshTokenParams{
		ID:        refreshTokenString,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		UserID:    userId,
		ExpiresAt: time.Now().Add(60 * 24 * time.Hour),
		RevokedAt: sql.NullTime{},
	}
}

func validateJWT(r *http.Request, w http.ResponseWriter, cfg *config) (uuid.UUID, bool) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		write401Error(w)
		return uuid.UUID{}, true
	}

	userUuid, err := auth.ValidateJWT(token, cfg.secret)
	if err != nil {
		write401Error(w)
		return uuid.UUID{}, true
	}
	return userUuid, false
}
func checkDBErrAndWriteErr(err error, w http.ResponseWriter, errorString string) bool {
	if err != nil {
		if strings.Contains(err.Error(), "no rows in result set") {
			write404ErrToResponse(w, errorString)
			return true
		}
		write404ErrToResponse(w, err.Error())
		return true

	}
	return false
}

func getValidatedChirpBody(chirpBody string) string {
	splitTrimmedStrings := getStrippedSplitStrings(chirpBody)
	validatedStrings := []string{}
	for _, splitTrimmedString := range splitTrimmedStrings {
		if _, ok := profaneStringMap[strings.ToLower(splitTrimmedString)]; ok {
			validatedStrings = append(validatedStrings, "****")
			continue
		}
		validatedStrings = append(validatedStrings, splitTrimmedString)
	}

	return strings.Join(validatedStrings, " ")
}

func validateChirpLength(body string) (isValid bool) {
	if len(body) > 140 {
		return false
	}
	return false
}

func write401Error(w http.ResponseWriter) {
	w.WriteHeader(401)
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("401 Unauthorized"))
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

func write404ErrToResponse(w http.ResponseWriter, errorString string) {

	errorStruct := errorJsonStruct{
		ErrorString: errorString,
	}
	marshalledData, err := json.Marshal(errorStruct)

	if err != nil {
		log.Printf("error marshalling JSON: %s", err)
		w.WriteHeader(404)
		return
	}

	w.WriteHeader(404)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(marshalledData))

}

func (cfg *config) createUsersHandler(w http.ResponseWriter, r *http.Request) {

	type createUserPayload struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	payloadJson := createUserPayload{}

	decoder := json.NewDecoder(r.Body)
	decodeErr := decoder.Decode(&payloadJson)
	if decodeErr != nil {
		writeErrToResponse(w, "bad request: payload could not be processed")
		return
	}
	if payloadJson.Email == "" || payloadJson.Password == "" {
		writeErrToResponse(w, "bad request: mandatory inputs not filled")
		return
	}

	user, createUserErr := createUser(payloadJson.Email, payloadJson.Password, cfg)
	if createUserErr != nil {
		writeErrToResponse(w, fmt.Sprintf("database error: %s", createUserErr.Error()))
		return
	}

	type createdUserStruct struct {
		ID          uuid.UUID `json:"id"`
		CreatedAt   time.Time `json:"created_at"`
		UpdatedAt   time.Time `json:"updated_at"`
		Email       string    `json:"email"`
		IsChirpyRed bool      `json:"is_chirpy_red"`
	}

	structToMarshal := createdUserStruct{
		ID:          user.ID,
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
		Email:       user.Email,
		IsChirpyRed: user.IsChirpyRed.Bool,
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
		return
	}
	w.WriteHeader(200)
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("Users have been successfully reset"))

}

func createUser(email, password string, cfg *config) (user database.User, err error) {
	hash, err := auth.HashPassword(password)
	if err != nil {
		return database.User{}, err
	}
	params := database.CreateUserParams{
		ID:        uuid.New(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Email:     email,
		HashedPassword: sql.NullString{
			String: hash,
			Valid:  true},
	}

	user, createUserErr := cfg.queries.CreateUser(context.Background(), params)
	if createUserErr != nil {
		return database.User{}, createUserErr
	}
	return user, nil
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

	returnedSlice := []string{}
	splitStrings := strings.Split(input, " ")
	for _, splitString := range splitStrings {
		returnedSlice = append(returnedSlice, strings.Trim(splitString, " "))
	}
	// for _, returnString := range returnedSlice {
	// }
	return returnedSlice
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
