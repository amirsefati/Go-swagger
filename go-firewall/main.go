package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go-firewall/api"
	"go-firewall/database"
	"go-firewall/monitor"
)

var (
	Version   = "1.0.0"
	BuildDate = time.Now().Format("2006-01-02")
)

func main() {
	log.Println("=================================================")
	log.Printf("  Go Firewall - Process Monitor v%s", Version)
	log.Printf("  Build Date: %s", BuildDate)
	log.Println("=================================================")

	if os.Getuid() != 0 {
		log.Println("WARNING: Running without root privileges. Some features may be limited.")
	}

	db, err := database.InitDatabase("firewall.db")
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	if err := monitor.InitKnownHashes(); err != nil {
		log.Printf("Warning: Failed to load known hashes: %v", err)
	}

	processMonitor := monitor.NewProcessMonitor(db)
	go processMonitor.Start()

	alertMonitor := monitor.NewAlertMonitor(db)
	go alertMonitor.Start()

	server := api.NewServer(db, processMonitor)
	go server.Start()

	log.Println("Firewall is running. Press Ctrl+C to stop.")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down...")
	processMonitor.Stop()
	alertMonitor.Stop()
	log.Println("Shutdown complete.")
}
