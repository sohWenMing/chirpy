package main

import (
	"net/http"
	"os"
)

func main() {
	mux := http.NewServeMux()
	//mux is the router that is passed into the server

	mux.HandleFunc("/healthz", healthCheckHandler)
	// user HandleFunc if we want to have a simple handling function  that interacts with the endpoint, without any requirements to access state

	fileServer := http.FileServer(http.Dir("."))
	/*
		fileServer is used to serve files to the user - in the event that the path of the request evaluates to "/", will serve index.html
		be default
	*/

	mux.Handle("/app/", http.StripPrefix("/app", fsWrapper(fileServer)))
	//use .Handle if you want to attach an actual handler, ie a struct that has a http.ServeHTTP method which defines it as a http.Handler interface

	server := &http.Server{
		Handler: mux,
		Addr:    ":8080",
	}
	/*
		note that app fields of the server should be set at instantiation and we should be interacting with a pointer to a server, and not
		a copy or value of a server
	*/

	server.ListenAndServe()
}

func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)
	w.Header().Set("content-type", "text/plain; charset=utf-8")
	w.Write([]byte("OK"))
}

func fsWrapper(fs http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			_, err := os.Stat("./index.html")
			if os.IsNotExist(err) {
				http.Error(w, "index not found", 404)
				return
			}
		}
		fs.ServeHTTP(w, r)
	})
}

/*
	fsWrapper returns a http Handler, as http.HandlerFunc returns a http Handler where there is an initial callback that will run
	defined by the func(w http.ResponseWriter, r *http.Request)
*/
