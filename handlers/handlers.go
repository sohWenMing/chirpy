package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/sohWenMing/chirpy/apiconfig"
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
	mux.HandleFunc("GET /admin/metrics", hitsHandler(config))
	mux.HandleFunc("POST /admin/reset", resetHandler(config))
	return mux
}

func writeJsonErrFunc(w http.ResponseWriter, errMsg string) {
	type jsonError struct {
		Error string `json:"error"`
	}
	jsonErr := jsonError{
		errMsg,
	}
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(400)
	bytes, _ := json.Marshal(jsonErr)
	w.Write(bytes)
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
			writeJsonErrFunc(w, fmt.Sprintf("an error occured: %s\n", err.Error()))
			return
		}
		user, err := apiConfig.Queries.CreateUser(ctx, emailStruct.Email)
		if err != nil {
			fmt.Println("error occured in creation: ", err.Error())
			writeJsonErrFunc(w, fmt.Sprintf("an error occured: %s\n", err.Error()))
			return
		}
		resBytes, err := json.Marshal(user)
		if err != nil {
			fmt.Println("error occured in marshalling: ", err.Error())
			writeJsonErrFunc(w, fmt.Sprintf("an error occured: %s\n", err.Error()))
			return
		}
		w.WriteHeader(201)
		w.Header().Add("Content-Type", "application/json")
		w.Write(resBytes)
		return
	}
}

func validateChirpHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	type jsonBody struct {
		Body string `json:"body"`
	}
	var requestBody jsonBody
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&requestBody); err != nil {
		writeJsonErrFunc(w, fmt.Sprintf("Something went wrong. error: %s", err.Error()))
		return
	}
	fmt.Println("requestBody: ", requestBody)
	if len(requestBody.Body) > 140 {
		writeJsonErrFunc(w, fmt.Sprintf("chirp is too long"))
		return
	}

	type validStruct struct {
		CleanedBody string `json:"cleaned_body"`
	}
	responseBody := validStruct{processing.CleanBody(requestBody.Body)}
	bytes, err := json.Marshal(responseBody)
	if err != nil {
		writeJsonErrFunc(w, fmt.Sprintf("something went wrong. Error: %s", err.Error()))
		return

	}
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write(bytes)
	return
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
		apiConfig.ResetHits()
		resetHits := apiConfig.GetFileServerHits()
		w.Header().Add("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(200)
		w.Write([]byte(fmt.Sprintf("Hits: %d\n", resetHits)))
	}
}
