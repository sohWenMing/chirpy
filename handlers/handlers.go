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
	mux.HandleFunc("GET /admin/metrics", hitsHandler(config))
	mux.HandleFunc("POST /admin/reset", resetHandler(config))
	return mux
}

func validateChirpHandler(w http.ResponseWriter, r *http.Request) {
	writeJsonErrFunc := func(w http.ResponseWriter, errMsg string) {
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
