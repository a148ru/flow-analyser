package web

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"flow-analyser/internal/config"
	"flow-analyser/internal/storage"
	"github.com/gorilla/mux"
)

// WebServer represents the web server
type WebServer struct {
	cfg    *config.Config
	store  *storage.FlowStore
	Router *mux.Router
}

// NewWebServer creates a new web server
func NewWebServer(cfg *config.Config, store *storage.FlowStore) *WebServer {
	ws := &WebServer{
		cfg:    cfg,
		store:  store,
		Router: mux.NewRouter(),
	}

	ws.setupRoutes()
	return ws
}

// setupRoutes sets up HTTP routes
func (ws *WebServer) setupRoutes() {
	// API endpoints
	ws.Router.HandleFunc("/api/flows", ws.handleFlows).Methods("GET")
	ws.Router.HandleFunc("/api/flows/top", ws.handleTopFlows).Methods("GET")
	ws.Router.HandleFunc("/api/stats", ws.handleStats).Methods("GET")
	ws.Router.HandleFunc("/api/protocols", ws.handleProtocols).Methods("GET")

	// Web UI
	ws.Router.HandleFunc("/", ws.handleIndex).Methods("GET")
	ws.Router.HandleFunc("/index.html", ws.handleIndex).Methods("GET")
	ws.Router.PathPrefix("/ui/").Handler(http.StripPrefix("/ui/", http.FileServer(http.Dir("/home/a148ru/flow-analyser/ui"))))

	// Static files
	ws.Router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))
}

// handleFlows handles GET /api/flows
func (ws *WebServer) handleFlows(w http.ResponseWriter, r *http.Request) {
	limit := getIntQuery(r, "limit", 100)
	offset := getIntQuery(r, "offset", 0)
	protocol := r.URL.Query().Get("protocol")

	flows := ws.store.GetFlows(limit, offset, protocol)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(flows)
}

// handleTopFlows handles GET /api/flows/top
func (ws *WebServer) handleTopFlows(w http.ResponseWriter, r *http.Request) {
	limit := getIntQuery(r, "limit", 20)

	topFlows := ws.store.GetTopFlowsByBytes(limit)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(topFlows)
}

// handleStats handles GET /api/stats
func (ws *WebServer) handleStats(w http.ResponseWriter, r *http.Request) {
	stats := map[string]interface{}{
		"total_flows": ws.store.Count(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// handleProtocols handles GET /api/protocols
func (ws *WebServer) handleProtocols(w http.ResponseWriter, r *http.Request) {
	protocols := []struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}{
		{Name: "ICMP", Count: 0},
		{Name: "TCP", Count: 0},
		{Name: "UDP", Count: 0},
		{Name: "GRE", Count: 0},
		{Name: "ESP", Count: 0},
		{Name: "AH", Count: 0},
		{Name: "OSPF", Count: 0},
		{Name: "SCTP", Count: 0},
		{Name: "Other", Count: 0},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(protocols)
}

// handleIndex handles the main page
func (ws *WebServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./ui/index.html")
}

// getIntQuery gets an integer query parameter
func getIntQuery(r *http.Request, name string, defaultValue int) int {
	value := r.URL.Query().Get(name)
	if value == "" {
		return defaultValue
	}
	fmt.Sscanf(value, "%d", &defaultValue)
	return defaultValue
}

// Start starts the web server
func (ws *WebServer) Start() {
	addr := fmt.Sprintf("%s:%d", ws.cfg.WebHost, ws.cfg.WebPort)
	log.Printf("Starting web server on %s", addr)
	if err := http.ListenAndServe(addr, ws.Router); err != nil {
		log.Fatal(err)
	}
}
