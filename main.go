package main

import (
	"embed"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/sohWenMing/chirpy/apiconfig"
	"github.com/sohWenMing/chirpy/databaseconnection"
	"github.com/sohWenMing/chirpy/envloader"
	"github.com/sohWenMing/chirpy/gooseutils"
	"github.com/sohWenMing/chirpy/handlers"
)

//go:embed sql/schema/*.sql
var embedMigrations embed.FS
var envPath = "./.env"

func main() {
	envConfig, err := envloader.LoadEnv(envPath)
	if err != nil {
		log.Fatal(err)
	}
	dbToQueries, err := databaseconnection.Connect(envConfig)
	if err != nil {
		log.Fatal(err)
	}
	migrationErr := gooseutils.RunMigrations(dbToQueries.DB, embedMigrations)
	if migrationErr != nil {
		log.Fatal(migrationErr)
	}
	apiConfig := apiconfig.InitApiConfig()
	apiConfig.SetDatabaseQueries(dbToQueries.Queries)
	apiConfig.SetPlatform(envConfig.GetPlatform())
	// init the server
	// start the server, on another go routine
	// get a channel
	srv := InitServer(":8080", apiConfig)
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

func InitServer(addr string, apiConfig *apiconfig.ApiConfig) *http.Server {
	srv := &http.Server{}
	srv.Addr = ":8080"
	mux := handlers.InitMuxHandler(apiConfig)
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
