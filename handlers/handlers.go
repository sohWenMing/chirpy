package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/sohWenMing/chirpy/apiconfig"
	"github.com/sohWenMing/chirpy/internal/database"
	"github.com/sohWenMing/chirpy/internal/modelprocessing"
	"github.com/sohWenMing/chirpy/processing"
)

func InitFileServerHandler(filePath string) http.Handler {
	return http.FileServer(http.Dir(filePath))
}

func InitMuxHandler(config *apiconfig.ApiConfig) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/app/", http.StripPrefix("/app/",
		config.MiddlewareMetricsInc(InitFileServerHandler("."))))
	mux.HandleFunc("GET /api/healthz", healthHandler)
	mux.HandleFunc("POST /api/validate_chirp", validateChirpHandler)
	mux.HandleFunc("POST /api/users", createUserHandler(config))
	mux.HandleFunc("GET /api/chirps/{id}", getChirp(config))
	mux.HandleFunc("GET /api/chirps", getChirps(config))
	mux.HandleFunc("POST /api/chirps", createChirp(config))
	mux.HandleFunc("GET /admin/metrics", hitsHandler(config))
	resetHandlerFunc := http.HandlerFunc(resetHandler(config))
	mux.HandleFunc("POST /admin/reset", checkPlatformMiddleWare(config, resetHandlerFunc))
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
		if err := validateChirp(chirp.Body); err != nil {
			writeJsonErrFunc(w, err.Error(), 400)
			return
		}
		uuid, err := uuid.Parse(chirp.UserId)
		if err != nil {
			writeJsonErrFunc(w, "user_id was not valid ", 400)
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
func createUserHandler(apiConfig *apiconfig.ApiConfig) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		defer r.Body.Close()

		type EmailStruct struct {
			Email string `json:"email"`
		}
		var emailStruct EmailStruct
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&emailStruct); err != nil {
			fmt.Println("error occured in decoder: ", err.Error())
			writeJsonErrFunc(w, fmt.Sprintf("an error occured: %s\n", err.Error()), 500)
			return
		}
		user, err := apiConfig.Queries.CreateUser(ctx, emailStruct.Email)
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
