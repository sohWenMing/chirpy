package main

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/sohWenMing/chirpy/handlers"
)

func main() {
	// init the server
	// start the server, on another go routine
	// get a channel
	srv := InitServer(":8080")
	go StartServer(srv)
	fmt.Println("server started on port 8080")
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	ListenForSignal(sigChan, srv)

}

func ListenForSignal(sigChan <-chan os.Signal, server *http.Server) {
	<-sigChan
	err := server.Close()
	if err != nil {
		fmt.Println("error when closing server: ", err)
	}
}

func InitServer(addr string) *http.Server {
	srv := &http.Server{}
	srv.Addr = ":8080"
	mux := handlers.InitMuxHandler()
	srv.Handler = mux
	return srv
}

func StartServer(server *http.Server) {
	if err := server.ListenAndServe(); err != nil {
		if err == http.ErrServerClosed {
			fmt.Println("server successfully shut down")
			os.Exit(0)
		} else {
			fmt.Println("error when closing server: ", err)
			os.Exit(1)
		}
	}
	fmt.Println("Server successfully close")
}
