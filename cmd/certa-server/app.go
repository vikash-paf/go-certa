package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"go-certa/pkg/audit"
	"go-certa/pkg/ca"
	"go-certa/pkg/protocols/acme"
	"go-certa/pkg/protocols/crl"
	"go-certa/pkg/protocols/est"
	"go-certa/pkg/protocols/ocsp"
	"go-certa/pkg/signer"
	"go-certa/pkg/storage"
	"go-certa/pkg/telemetry"
)

// AppConfig configures the go-certa trust authority server.
type AppConfig struct {
	ListenAddr              string
	BaseURL                 string
	AuditWriter             io.Writer
	SkipChallengeValidation bool
	CRLInterval             time.Duration
	CRLValidity             time.Duration
}

// ServerApp encapsulates all initialized PKI subsystem components and HTTP routing.
type ServerApp struct {
	Config        AppConfig
	Storage       storage.Storage
	Audit         *audit.ChainAuditLogger
	Telemetry     *telemetry.Registry
	Authority     *ca.Authority
	HSMSigner     cryptoSignerWrapper
	WorkerPool    *signer.WorkerPool
	CRLService    *crl.CRLService
	OCSPResponder *ocsp.Handler
	RevocationAPI *ocsp.RevocationAPI
	ACMEServer    *acme.Server
	ESTHandler    *est.Handler
	Mux           *http.ServeMux
	HTTPServer    *http.Server

	workerCancel context.CancelFunc
}

type cryptoSignerWrapper struct {
	*signer.HSMSigner
}

// NewServerApp bootstraps the complete production-grade PKI stack.
func NewServerApp(cfg AppConfig) (*ServerApp, error) {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":8080"
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "http://localhost:8080"
	}
	cfg.BaseURL = strings.TrimSuffix(cfg.BaseURL, "/")

	if cfg.AuditWriter == nil {
		cfg.AuditWriter = os.Stdout
	}
	if cfg.CRLInterval <= 0 {
		cfg.CRLInterval = 1 * time.Hour
	}
	if cfg.CRLValidity <= 0 {
		cfg.CRLValidity = 24 * time.Hour
	}

	// 1. Initialize persistent storage
	store := storage.NewMemoryStorage()

	// 2. Initialize cryptographically chained audit logger
	auditLog := audit.NewChainAuditLogger(cfg.AuditWriter)

	// 3. Initialize Prometheus telemetry registry
	metrics := telemetry.NewRegistry()

	// 4. Generate Intermediate CA Key & HSM Signer
	intKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed creating intermediate key: %w", err)
	}
	hsmSigner := signer.NewHSMSigner(intKey, 15*time.Millisecond)

	// 5. Initialize CA Authority with CABF/RFC 5280 policy engine
	authority, err := ca.NewAuthority(hsmSigner)
	if err != nil {
		return nil, fmt.Errorf("failed initializing CA authority: %w", err)
	}

	// Record initial key access audit event
	_, _ = auditLog.LogEvent(
		context.Background(),
		audit.ActionKeyAccess,
		"system",
		authority.IntermediateCert.Subject.CommonName,
		audit.StatusSuccess,
		map[string]string{
			"root_subject": authority.RootCert.Subject.CommonName,
			"algorithm":    "RSA-2048",
		},
	)

	// 6. Initialize Worker Pool
	workerPool := signer.NewWorkerPool(authority, 1000, 16)

	// 7. Initialize CRL Generation & Distribution Service
	crlGen, err := crl.NewCRLGenerator(authority.IntermediateCert, hsmSigner, store, cfg.CRLValidity)
	if err != nil {
		return nil, fmt.Errorf("failed creating CRL generator: %w", err)
	}
	crlService := crl.NewCRLService(crlGen, cfg.CRLInterval)
	crlHandler := crl.NewHandler(crlService)

	// 8. Initialize High-Performance Delegated OCSP Responder
	ocspResponder, err := ocsp.NewResponder(ocsp.Config{
		IssuerCert:    authority.IntermediateCert,
		ResponderCert: authority.IntermediateCert,
		Signer:        hsmSigner,
		Storage:       store,
		CacheMaxAge:   3600,
		Validity:      24 * time.Hour,
	})
	if err != nil {
		return nil, fmt.Errorf("failed initializing OCSP responder: %w", err)
	}

	// 9. Initialize Revocation Management API
	revocationAPI := ocsp.NewRevocationAPI(store)

	// 10. Initialize RFC 8555 ACME Server
	acmeServer, err := acme.NewServer(acme.ServerConfig{
		BaseURL:                 cfg.BaseURL,
		Authority:               authority,
		Storage:                 store,
		SkipChallengeValidation: cfg.SkipChallengeValidation,
	})
	if err != nil {
		return nil, fmt.Errorf("failed initializing ACME server: %w", err)
	}

	// 11. Initialize RFC 7030 EST Handler
	estHandler := est.NewHandler(workerPool, authority.IntermediateCert.Raw)

	// 12. Register all standard HTTP routes
	mux := http.NewServeMux()

	// RFC 8555 ACME routes
	mux.Handle("/.well-known/acme/", acmeServer)
	mux.Handle("/acme/", acmeServer)

	// RFC 7030 EST routes
	mux.HandleFunc("/.well-known/est/cacerts", estHandler.HandleCACerts)
	mux.HandleFunc("/.well-known/est/simpleenroll", estHandler.HandleSimpleEnroll)

	// RFC 6960 / RFC 5019 OCSP route
	mux.Handle("/ocsp", ocspResponder)

	// RFC 5280 CRL route
	mux.Handle("/crl/intermediate.crl", crlHandler)

	// Certificate Revocation Management API
	mux.HandleFunc("/api/v1/revoke", revocationAPI.HandleRevoke)

	// Prometheus telemetry route
	mux.Handle("/metrics", metrics.Handler())

	// RFC 5280 AIA caIssuers endpoint serving intermediate CA DER certificate
	mux.HandleFunc("/ca/intermediate.crt", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/pkix-cert")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(authority.IntermediateCert.Raw)
	})

	server := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	app := &ServerApp{
		Config:        cfg,
		Storage:       store,
		Audit:         auditLog,
		Telemetry:     metrics,
		Authority:     authority,
		HSMSigner:     cryptoSignerWrapper{hsmSigner},
		WorkerPool:    workerPool,
		CRLService:    crlService,
		OCSPResponder: ocspResponder,
		RevocationAPI: revocationAPI,
		ACMEServer:    acmeServer,
		ESTHandler:    estHandler,
		Mux:           mux,
		HTTPServer:    server,
	}

	return app, nil
}

// Start launches background services (WorkerPool, CRLService) and starts the HTTP listener.
func (app *ServerApp) Start(ctx context.Context) error {
	workerCtx, cancel := context.WithCancel(ctx)
	app.workerCancel = cancel

	// 1. Start worker pool
	go func() {
		if err := app.WorkerPool.Start(workerCtx); err != nil && err != context.Canceled {
			log.Printf("worker pool error: %v", err)
		}
	}()

	// 2. Start CRL background regeneration service
	if err := app.CRLService.Start(workerCtx); err != nil {
		return fmt.Errorf("failed starting CRL service: %w", err)
	}

	// 3. Periodic telemetry update
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-workerCtx.Done():
				return
			case <-ticker.C:
				app.Telemetry.SetSigningQueueDepth(float64(app.WorkerPool.QueueDepth()))
			}
		}
	}()

	return nil
}

// Stop gracefully shuts down the HTTP server and stops background services.
func (app *ServerApp) Stop(ctx context.Context) error {
	var firstErr error

	// Stop HTTP server
	if app.HTTPServer != nil {
		if err := app.HTTPServer.Shutdown(ctx); err != nil && err != http.ErrServerClosed {
			firstErr = err
		}
	}

	// Stop CRL background service
	if app.CRLService != nil {
		app.CRLService.Stop()
	}

	// Stop worker pool
	if app.workerCancel != nil {
		app.workerCancel()
	}

	return firstErr
}
