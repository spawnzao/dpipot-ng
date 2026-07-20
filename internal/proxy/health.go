package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/spawnzao/dpipot-ng/internal/kafka"
	"go.uber.org/zap"
)

type HealthServer struct {
	httpServer *http.Server
	producer   *kafka.Producer
	log        *zap.Logger
}

type HealthResponse struct {
	Status    string            `json:"status"`
	Timestamp string            `json:"timestamp"`
	Checks    map[string]string `json:"checks,omitempty"`
}

func NewHealthServer(addr string, producer *kafka.Producer, log *zap.Logger) *HealthServer {
	mux := http.NewServeMux()
	hs := &HealthServer{
		producer: producer,
		log:      log,
	}

	mux.HandleFunc("/healthz", hs.handleHealth)
	mux.HandleFunc("/healthz/ready", hs.handleReady)
	mux.HandleFunc("/healthz/live", hs.handleLive)

	hs.httpServer = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	return hs
}

func (h *HealthServer) Start() error {
	h.log.Info("health server escutando", zap.String("addr", h.httpServer.Addr))
	return h.httpServer.ListenAndServe()
}

func (h *HealthServer) Shutdown(ctx context.Context) error {
	return h.httpServer.Shutdown(ctx)
}

func (h *HealthServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	resp := HealthResponse{
		Status:    "ok",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Checks:    make(map[string]string),
	}

	if h.producer == nil {
		resp.Checks["kafka"] = "disabled"
	} else if h.producer.IsHealthy() {
		resp.Checks["kafka"] = "healthy"
	} else {
		resp.Checks["kafka"] = "unhealthy"
		resp.Status = "degraded"
	}

	w.Header().Set("Content-Type", "application/json")
	if resp.Status == "ok" {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	json.NewEncoder(w).Encode(resp)
}

func (h *HealthServer) handleReady(w http.ResponseWriter, r *http.Request) {
	if h.producer != nil && !h.producer.IsHealthy() {
		http.Error(w, "Kafka not ready", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
}

func (h *HealthServer) handleLive(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Last-resort liveness check: if Kafka has had zero confirmed deliveries for
	// >4 min (watchdog reconnect attempts failed), fail liveness so Kubernetes
	// restarts the pod and the watchdog gets a fresh start with new DNS resolution.
	if h.producer != nil && !h.producer.IsHealthy() {
		since := time.Since(h.producer.LastOK())
		if since > 4*time.Minute {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":          "unhealthy",
				"kafka_down_secs": int(since.Seconds()),
			})
			return
		}
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "alive"})
}
