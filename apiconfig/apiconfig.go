package apiconfig

import (
	"net/http"
	"sync/atomic"
)

type ApiConfig struct {
	fileServerHits atomic.Int32
}

func InitApiConfig() *ApiConfig {
	config := &ApiConfig{}
	return config
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
