package web

import (
	"encoding/json"
	"net/http"

	"flow-analyser/internal/storage"
)

// APIResponse represents a generic API response
type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// FlowResponse represents a flow response with additional info
type FlowResponse struct {
	Flow      storage.FlowEntry `json:"flow"`
	RouterIP  string            `json:"router_ip"`
	Timestamp string            `json:"timestamp"`
}

// StatsResponse represents server statistics
type StatsResponse struct {
	TotalFlows int `json:"total_flows"`
	TopFlows   int `json:"top_flows"`
	Sampling   int `json:"sampling"`
}

// ProtocolStats represents protocol statistics
type ProtocolStats struct {
	Protocol string `json:"protocol"`
	Count    int    `json:"count"`
	Bytes    uint64 `json:"bytes"`
}

// JSONResponse writes a JSON response
func JSONResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// WriteError writes an error response
func WriteError(w http.ResponseWriter, status int, message string) {
	JSONResponse(w, status, APIResponse{
		Success: false,
		Error:   message,
	})
}

// WriteSuccess writes a success response
func WriteSuccess(w http.ResponseWriter, data interface{}) {
	JSONResponse(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    data,
	})
}

// WriteNotFound writes a 404 response
func WriteNotFound(w http.ResponseWriter) {
	WriteError(w, http.StatusNotFound, "Resource not found")
}

// WriteBadRequest writes a 400 response
func WriteBadRequest(w http.ResponseWriter, message string) {
	WriteError(w, http.StatusBadRequest, message)
}

// WriteServerError writes a 500 response
func WriteServerError(w http.ResponseWriter, message string) {
	WriteError(w, http.StatusInternalServerError, message)
}
