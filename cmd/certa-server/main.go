package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	log.Println("Initializing go-certa Digital Trust Authority...")

	app, err := NewServerApp(AppConfig{
		ListenAddr:              ":8080",
		BaseURL:                 "http://localhost:8080",
		AuditWriter:             os.Stdout,
		SkipChallengeValidation: false,
		CRLInterval:             1 * time.Hour,
		CRLValidity:             24 * time.Hour,
	})
	if err != nil {
		log.Fatalf("failed bootstrapping go-certa server: %v", err)
	}

	log.Printf("Verified Root CA: %s", app.Authority.RootCert.Subject.CommonName)
	log.Printf("Verified Intermediate CA: %s", app.Authority.IntermediateCert.Subject.CommonName)

	serverCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := app.Start(serverCtx); err != nil {
		log.Fatalf("failed starting background services: %v", err)
	}

	go func() {
		log.Printf("Server online on http://localhost%s", app.Config.ListenAddr)
		if err := app.HTTPServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down go-certa gracefully...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := app.Stop(shutdownCtx); err != nil {
		log.Printf("shutdown error: %v", err)
	}

	// Verify cryptographic audit log chain before terminating
	if valid, err := app.Audit.VerifyChain(); valid && err == nil {
		log.Printf("Audit log cryptographic hash chain verified (%d events)", app.Audit.EventCount())
	} else {
		log.Printf("WARNING: Audit log verification error: %v", err)
	}

	log.Println("Shutdown complete.")
}
