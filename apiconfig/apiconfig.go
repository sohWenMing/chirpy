package apiconfig

import (
	"net/http"
	"sync/atomic"

	"github.com/sohWenMing/chirpy/internal/database"
)

type ApiConfig struct {
	fileServerHits atomic.Int32
	Queries        *database.Queries
}

func InitApiConfig() *ApiConfig {
	config := &ApiConfig{}
	return config
}

func (a *ApiConfig) SetDatabaseQueries(queries *database.Queries) {
	a.Queries = queries
	return
}

func (a *ApiConfig) MiddlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.fileServerHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (a *ApiConfig) GetFileServerHits() int {
	return int(a.fileServerHits.Load())
}
func (a *ApiConfig) ResetHits() {
	a.fileServerHits.Store(int32(0))
}
