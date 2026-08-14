package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go-certa/pkg/ca"
	"go-certa/pkg/protocols/est"
	"go-certa/pkg/protocols/ocsp"
	"go-certa/pkg/signer"
)

func main() {
	log.Println("Initializing go-certa Digital Trust Authority...")

	intKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("failed creating intermediate key: %v", err)
	}
	hsmSigner := signer.NewHSMSigner(intKey, 15*time.Millisecond)

	authority, err := ca.NewAuthority(hsmSigner)
	if err != nil {
		log.Fatalf("failed initializing CA authority: %v", err)
	}
	log.Printf("Verified Root CA: %s", authority.RootCert.Subject.CommonName)
	log.Printf("Verified Intermediate CA: %s", authority.IntermediateCert.Subject.CommonName)

	workerPool := signer.NewWorkerPool(authority, 1000, 16)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := workerPool.Start(ctx); err != nil {
			log.Printf("worker pool error: %v", err)
		}
	}()

	revocationStore := ocsp.NewMemoryRevocationStore()
	ocspHandler := ocsp.NewHandler(authority.IntermediateCert, hsmSigner, revocationStore)
	estHandler := est.NewHandler(workerPool, authority.IntermediateCert.Raw)

	mux := http.NewServeMux()
	mux.Handle("/ocsp", ocspHandler)
	mux.HandleFunc("/.well-known/est/cacerts", estHandler.HandleCACerts)
	mux.HandleFunc("/.well-known/est/simpleenroll", estHandler.HandleSimpleEnroll)

	server := &http.Server{
		Addr:         ":8080",
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		log.Println("Server online on http://localhost:8080")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down go-certa gracefully...")
	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	server.Shutdown(shutdownCtx)
	log.Println("Shutdown complete.")
}
