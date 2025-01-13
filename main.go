package main

import (
	"fmt"
	"net/http"
	"os"
	"sync/atomic"
)

func main() {
	cfg := config{}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", healthCheckHandler)
	mux.HandleFunc("GET /metrics", cfg.metricsHandler)
	mux.HandleFunc("POST /reset", func(w http.ResponseWriter, r *http.Request) {
		cfg.fileServerHits.Store(0)
		w.Header().Set("content-type", "text/plain; charset=UTF-8")
		w.WriteHeader(http.StatusOK)
	})
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

func (cfg *config) metricsHandler(w http.ResponseWriter, _ *http.Request) {
	hits := cfg.fileServerHits.Load()
	w.WriteHeader(http.StatusOK)
	w.Header().Set("content-type", "text/plain; charset=UTF-8")
	w.Write([]byte(fmt.Sprintf("Hits: %d", hits)))
}

func (cfg *config) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		cfg.fileServerHits.Add(1)
		next.ServeHTTP(w, r)
	})

}
func baseHandler(w http.ResponseWriter, r *http.Request) {

	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte("Placeholder for 404 not found"))
}

func healthCheckHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Header().Set("content-type", "text/plain; charset=UTF-8")
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
