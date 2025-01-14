package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
)

var profaneStringMap = map[string]bool{
	"kerfuffle": true,
	"sharbert":  true,
	"fornax":    true,
}

func main() {
	cfg := config{}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/healthz", healthCheckHandler)
	mux.HandleFunc("GET /admin/metrics", cfg.metricsHandler)
	mux.HandleFunc("POST /admin/reset", func(w http.ResponseWriter, r *http.Request) {
		cfg.fileServerHits.Store(0)
		w.Header().Set("content-type", "text/plain; charset=UTF-8")
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("POST /api/validate_chirp", validateChirpHandler)
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

type config struct {
	fileServerHits atomic.Int32
}

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

type validStruct struct {
	ValidString bool `json:"valid"`
}

type errorJsonStruct struct {
	ErrorString string `json:"error"`
}
