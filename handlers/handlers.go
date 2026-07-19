package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/sohWenMing/chirpy/apiconfig"
	"github.com/sohWenMing/chirpy/internal/auth"
	internalauth "github.com/sohWenMing/chirpy/internal/auth"
	"github.com/sohWenMing/chirpy/internal/database"
	"github.com/sohWenMing/chirpy/internal/modelprocessing"
	"github.com/sohWenMing/chirpy/processing"
)

func InitFileServerHandler(filePath string) http.Handler {
	return http.FileServer(http.Dir(filePath))
}

func InitMuxHandler(config *apiconfig.ApiConfig) *http.ServeMux {

	resetHandlerFunc := http.HandlerFunc(resetHandler(config))
	mux := http.NewServeMux()

	mux.Handle("/app/", http.StripPrefix("/app/",
		config.MiddlewareMetricsInc(InitFileServerHandler("."))))
	mux.HandleFunc("GET /api/healthz", healthHandler)
	mux.HandleFunc("POST /api/validate_chirp", validateChirpHandler)
	mux.HandleFunc("POST /api/users", createUserHandler(config))
	mux.HandleFunc("PUT /api/users", updateUserHandler(config))
	mux.HandleFunc("POST /api/refresh", refreshHandler(config))
	mux.HandleFunc("POST /api/revoke", revokeHandler(config))
	mux.HandleFunc("GET /api/chirps/{id}", getChirp(config))
	mux.HandleFunc("GET /api/chirps", getChirps(config))
	mux.HandleFunc("POST /api/chirps", createChirp(config))
	mux.HandleFunc("POST /api/login", loginUserHandler(config))
	mux.HandleFunc("GET /admin/metrics", hitsHandler(config))
	mux.HandleFunc("POST /admin/reset", checkPlatformMiddleWare(config, resetHandlerFunc))
	mux.HandleFunc("DELETE /api/chirps/{id}", deleteHandler(config))
	return mux
}

func writeJsonErrFunc(w http.ResponseWriter, errMsg string, statusCode int) {
	type jsonError struct {
		Error string `json:"error"`
	}
	jsonErr := jsonError{
		errMsg,
	}
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	bytes, _ := json.Marshal(jsonErr)
	w.Write(bytes)
}
func getChirp(apiConfig *apiconfig.ApiConfig) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		fmt.Println("id: ", id)
		uuidId, err := uuid.Parse(id)
		if err != nil {
			writeJsonErrFunc(w, fmt.Sprintf("Id: %s wa not valid\n", id), 404)
			return
		}
		chirp, err := apiConfig.Queries.GetChirp(r.Context(), uuidId)
		if err != nil {
			switch errors.Is(err, sql.ErrNoRows) {
			case true:
				writeJsonErrFunc(w, "The id did not return any chirps", 404)
				return
			default:
				writeJsonErrFunc(w, err.Error(), 404)
				return
			}
		}
		bytes, err := modelprocessing.RepresentChirp(chirp)
		if err != nil {
			writeJsonErrFunc(w, err.Error(), 500)
			return
		}
		w.WriteHeader(200)
		w.Write(bytes)
		return
	}
}

func getChirps(apiConfig *apiconfig.ApiConfig) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		chirps, err := apiConfig.Queries.GetChirps(r.Context())
		if err != nil {
			writeJsonErrFunc(w, err.Error(), 400)
			return
		}
		reprChirps := make([]modelprocessing.ReprChirp, len(chirps))
		for i, chirp := range chirps {
			reprChirps[i] = modelprocessing.MapDBChirpToReprChirp(chirp)
		}

		bytes, err := json.Marshal(reprChirps)
		if err != nil {
			writeJsonErrFunc(w, err.Error(), 400)
			return
		}
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(bytes)

	}
}

func createChirp(apiConfig *apiconfig.ApiConfig) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		bearerToken, err := internalauth.GetBearerToken(r.Header)
		if err != nil {
			fmt.Println("error occured when trying to get bearerToken", bearerToken)
			writeJsonErrFunc(w, "bearer token not found", 401)
			return
		}
		userId, err := internalauth.ValidateJWT(bearerToken, apiConfig.SecretKey)
		if err != nil {
			fmt.Println("error occured when validatingJWT", bearerToken)
			writeJsonErrFunc(w, err.Error(), 401)
			return
		}
		type chirpStruct struct {
			Body   string `json:"body"`
			UserId string `json:"user_id"`
		}
		var chirp chirpStruct
		defer r.Body.Close()
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&chirp); err != nil {
			writeJsonErrFunc(w, "error parsing input", 500)
			return
		}
		chirp.UserId = userId.String()
		if err := validateChirp(chirp.Body); err != nil {
			writeJsonErrFunc(w, err.Error(), 401)
			return
		}
		uuid, err := uuid.Parse(chirp.UserId)
		if err != nil {
			writeJsonErrFunc(w, "user_id was not valid ", 401)
			return
		}
		params := database.CreateChirpParams{
			Body:   chirp.Body,
			UserID: uuid,
		}
		returnedChirp, err := apiConfig.Queries.CreateChirp(r.Context(), params)
		if err != nil {
			writeJsonErrFunc(w, "user_id was not valid ", 400)
			return
		}
		reprChirp, err := modelprocessing.RepresentChirp(returnedChirp)
		if err != nil {
			writeJsonErrFunc(w, err.Error(), 500)
			return
		}
		w.WriteHeader(201)
		w.Write([]byte(reprChirp))
	}
}

func validateChirp(chirp string) (err error) {
	fmt.Println("got into validate function ")
	fmt.Println("length of chirp: ", len(chirp))
	if len(chirp) > 140 {
		return errors.New("chirp length cannot be more that 140 characters")
	}
	return nil
}

func validateChirpHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	type jsonBody struct {
		Body string `json:"body"`
	}
	var requestBody jsonBody
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&requestBody); err != nil {
		writeJsonErrFunc(w, fmt.Sprintf("Something went wrong. error: %s", err.Error()), 500)
		return
	}
	fmt.Println("requestBody: ", requestBody)
	if len(requestBody.Body) > 140 {
		writeJsonErrFunc(w, fmt.Sprintf("chirp is too long"), 401)
		return
	}

	type validStruct struct {
		CleanedBody string `json:"cleaned_body"`
	}
	responseBody := validStruct{processing.CleanBody(requestBody.Body)}
	bytes, err := json.Marshal(responseBody)
	if err != nil {
		writeJsonErrFunc(w, fmt.Sprintf("something went wrong. Error: %s", err.Error()), 500)
		return

	}
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write(bytes)
	return
}

type UserDetails struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	// ExpiresIn int    `json:"expires_in"`
}

func getUserDetailsFromRequest(r *http.Request) (details UserDetails, err error) {
	fmt.Println("from within getUserDetailsFromRequest")
	// bodyBytes, _ := io.ReadAll(r.Body)
	// fmt.Println("bodyBytes: ", string(bodyBytes))
	var userDetails UserDetails
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&userDetails); err != nil {
		fmt.Println("error: %v\n", err)
		return UserDetails{}, err
	}
	return userDetails, nil
}

func loginUserHandler(apiConfig *apiconfig.ApiConfig) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		userDetails, err := getUserDetailsFromRequest(r)
		if err != nil {
			writeJsonErrFunc(w, "user details were not valid", 400)
			return
		}
		userFromDB, err := apiConfig.Queries.GetUserByEmail(r.Context(), userDetails.Email)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				writeJsonErrFunc(w, "user could not be found with this email", 401)
				return
			} else {
				writeJsonErrFunc(w, err.Error(), 500)
				return
			}
		}
		isValid, err := internalauth.CompareHashAndPassword(userDetails.Password, userFromDB.HashedPassword)
		if err != nil {
			writeJsonErrFunc(w, "an internal error occured", 500)
			return
		}
		if !isValid {
			writeJsonErrFunc(w, "the login details are not correct", 401)
			return
		}

		jwtToken, err := auth.MakeJWT(userFromDB.ID, apiConfig.SecretKey, 60*time.Minute)
		if err != nil {
			writeJsonErrFunc(w, "internal error", 500)
			return
		}
		createdToken := auth.MakeRefreshToken()
		fmt.Println("created token: ", createdToken)

		params := database.CreateRefreshTokenParams{
			Token:  createdToken,
			UserID: userFromDB.ID,
		}

		refreshToken, err := apiConfig.Queries.CreateRefreshToken(r.Context(), params)
		if err != nil {
			writeJsonErrFunc(w, "internal error", 500)
			return
		}

		reprUser, err := modelprocessing.RepresentUserandToken(userFromDB, jwtToken, refreshToken.Token)
		if err != nil {
			writeJsonErrFunc(w, "error processing returned user", 500)
			return
		}
		w.WriteHeader(200)
		w.Header().Add("Content-Type", "application/json")
		w.Write(reprUser)
		return
	}
}

func createUserHandler(apiConfig *apiconfig.ApiConfig) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		defer r.Body.Close()
		fmt.Println("within create user handler")
		userDetails, err := getUserDetailsFromRequest(r)
		fmt.Println("userDetails: ", userDetails)
		if err != nil {
			writeJsonErrFunc(w, "user details were not valid", 400)
			return
		}
		if len(userDetails.Password) == 0 {
			writeJsonErrFunc(w, "user cannot be created without password", 400)
		}
		hashedPassword, err := internalauth.HashPassword(userDetails.Password)
		if err != nil {
			writeJsonErrFunc(w, "error processing password", 500)
			return
		}

		params := database.CreateUserParams{
			Email:          userDetails.Email,
			HashedPassword: hashedPassword,
		}

		user, err := apiConfig.Queries.CreateUser(ctx, params)
		if err != nil {
			fmt.Println("error occured in creation: ", err.Error())
			writeJsonErrFunc(w, fmt.Sprintf("an error occured: %s\n", err.Error()), 500)
			return
		}
		resBytes, err := modelprocessing.RepresentUser(user)
		if err != nil {
			fmt.Println("error occured in marshalling: ", err.Error())
			writeJsonErrFunc(w, fmt.Sprintf("an error occured: %s\n", err.Error()), 500)
			return
		}
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(201)
		w.Write(resBytes)
		return
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	w.Write([]byte("OK"))
	return
}

func hitsHandler(apiConfig *apiconfig.ApiConfig) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		hits := apiConfig.GetFileServerHits()
		w.Header().Add("Content-Type", "text/html")
		w.WriteHeader(200)
		w.Write([]byte(fmt.Sprintf(`
			<html>
  			<body>
     			<h1>Welcome, Chirpy Admin</h1>
        		<p>Chirpy has been visited %d times!</p>
          	</body>
        </html>`, hits)))
		return
	}
}

func resetHandler(apiConfig *apiconfig.ApiConfig) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		err := apiConfig.Queries.DeleteUsers(r.Context())
		if err != nil {
			w.WriteHeader(500)
			w.Write([]byte(fmt.Sprintf("Server Internal Error: %s\n", err.Error())))
			return
		}
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	}
}

func refreshHandler(apiConfig *apiconfig.ApiConfig) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		bearerToken, err := auth.GetBearerToken(r.Header)
		if err != nil {
			writeJsonErrFunc(w, err.Error(), 401)
			return
		}

		row, err := apiConfig.Queries.GetValidRefreshToken(r.Context(), bearerToken)
		if err != nil {
			writeJsonErrFunc(w, err.Error(), 401)
			return
		}

		jwt, err := auth.MakeJWT(row.UserID, apiConfig.SecretKey, 60*time.Minute)
		if err != nil {
			writeJsonErrFunc(w, err.Error(), 500)
			return
		}
		type tokenResponse struct {
			Token string `json:"token"`
		}
		response := tokenResponse{jwt}
		bytes, err := json.Marshal(response)
		if err != nil {
			writeJsonErrFunc(w, err.Error(), 500)
			return
		}
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(bytes)
		return
	}

}
func revokeHandler(apiConfig *apiconfig.ApiConfig) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		bearerToken, err := auth.GetBearerToken(r.Header)
		fmt.Println("bearerToken: ", bearerToken)
		if err != nil {
			writeJsonErrFunc(w, err.Error(), 401)
			return
		}
		if err := apiConfig.Queries.RevokeRefreshToken(r.Context(), bearerToken); err != nil {
			writeJsonErrFunc(w, err.Error(), 401)
			return
		}
		w.WriteHeader(204)
		return
	}
}

func updateUserHandler(config *apiconfig.ApiConfig) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		bearerToken, err := auth.GetBearerToken(r.Header)
		if err != nil {
			writeJsonErrFunc(w, err.Error(), 401)
			return
		}
		userId, err := auth.ValidateJWT(bearerToken, config.SecretKey)
		if err != nil {
			writeJsonErrFunc(w, err.Error(), 401)
			return
		}

		userDetails, err := getUserDetailsFromRequest(r)
		if err != nil {
			writeJsonErrFunc(w, err.Error(), 401)
			return
		}

		hashedPassword, err := auth.HashPassword(userDetails.Password)
		if err != nil {
			writeJsonErrFunc(w, err.Error(), 401)
			return
		}

		params := database.UpdateUserParams{
			Email:          userDetails.Email,
			HashedPassword: hashedPassword,
			ID:             userId,
		}

		returnedUser, err := config.Queries.UpdateUser(r.Context(), params)
		if err != nil {
			writeJsonErrFunc(w, err.Error(), 401)
			return
		}
		bytes, err := modelprocessing.RepresentUserRetrievedByEmail(returnedUser)
		if err != nil {
			writeJsonErrFunc(w, err.Error(), 401)
			return
		}
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(bytes)
		return
	}
}

func deleteHandler(config *apiconfig.ApiConfig) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		bearerToken, err := auth.GetBearerToken(r.Header)
		if err != nil {
			writeJsonErrFunc(w, err.Error(), 401)
			return
		}
		userId, err := auth.ValidateJWT(bearerToken, config.SecretKey)
		if err != nil {
			writeJsonErrFunc(w, err.Error(), 401)
			return
		}

		chirpId := r.PathValue("id")
		if chirpId == "" {
			if err != nil {
				writeJsonErrFunc(w, "chirp not found", 404)
				return
			}
		}
		parsedChirpId, err := uuid.Parse(chirpId)
		if err != nil {
			writeJsonErrFunc(w, "chirp not found", 404)
			return
		}

		retrievedChirp, err := config.Queries.GetChirp(r.Context(), parsedChirpId)
		if err != nil {
			writeJsonErrFunc(w, "chirp not found", 404)
			return
		}

		if retrievedChirp.UserID != userId {
			writeJsonErrFunc(w, "user not authorized", 403)
			return
		}

		if err := config.Queries.DeleteChirp(r.Context(), retrievedChirp.ID); err != nil {
			writeJsonErrFunc(w, "Internal error", 500)
			return
		}
		w.WriteHeader(204)
		return
	}
}

func checkPlatformMiddleWare(
	apiConfig *apiconfig.ApiConfig,
	next http.Handler) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if apiConfig.GetPlatform() != "dev" {
			w.WriteHeader(403)
			w.Write([]byte("forbidden"))
			return
		}
		next.ServeHTTP(w, r)
	}
}
