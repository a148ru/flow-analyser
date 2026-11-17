package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"flow-analyser/internal/config"
	"flow-analyser/internal/netflow"
	"flow-analyser/internal/storage"
	"flow-analyser/internal/web"
)

func main() {
	// Load configuration
	cfg := config.LoadConfig()

	// Initialize storage
	store := storage.NewFlowStore()

	// Initialize NetFlow handler
	nfHandler := netflow.NewNetFlowHandler(cfg, store)

	// Start NetFlow listener
	go nfHandler.StartListener()

	// Initialize web server
	webServer := web.NewWebServer(cfg, store)

	// Start web server
	go func() {
		addr := fmt.Sprintf("%s:%d", cfg.WebHost, cfg.WebPort)
		log.Printf("Starting web server on %s", addr)
		if err := http.ListenAndServe(addr, webServer.Router); err != nil {
			log.Fatalf("Web server error: %v", err)
		}
	}()

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigChan
	log.Printf("Received signal %v, shutting down...", sig)

	// Shutdown handlers
	nfHandler.StopListener()
	log.Println("NetFlow listener stopped")
	log.Println("Shutdown complete")
}
