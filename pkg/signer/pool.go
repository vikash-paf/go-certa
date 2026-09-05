package signer

import (
	"context"
	"math/big"
	"time"

	"golang.org/x/sync/errgroup"
)

// SignRequest represents a request queued for certificate signing.
type SignRequest struct {
	CSRDER   []byte
	Serial   *big.Int
	Validity time.Duration
	DNSNames []string
	ResChan  chan SignResponse
}

// SignResponse represents the output of a certificate signing request.
type SignResponse struct {
	CertDER []byte
	Err     error
}

// WorkerPool manages a concurrent pool of signing workers to bottleneck-protect the signer.
type WorkerPool struct {
	jobs    chan SignRequest
	issuer  Issuer
	workers int
}

// Issuer defines the capability to sign certificates.
type Issuer interface {
	SignCertificate(csrDER []byte, serial *big.Int, validity time.Duration, dnsNames []string) ([]byte, error)
}

// NewWorkerPool initializes a WorkerPool.
func NewWorkerPool(issuer Issuer, queueSize int, workers int) *WorkerPool {
	return &WorkerPool{
		jobs:    make(chan SignRequest, queueSize),
		issuer:  issuer,
		workers: workers,
	}
}

// Start spawns the workers and listens for signing requests until the context is cancelled.
func (wp *WorkerPool) Start(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	for i := 0; i < wp.workers; i++ {
		g.Go(func() error {
			for {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case req, ok := <-wp.jobs:
					if !ok {
						return nil
					}
					cert, err := wp.issuer.SignCertificate(req.CSRDER, req.Serial, req.Validity, req.DNSNames)
					req.ResChan <- SignResponse{CertDER: cert, Err: err}
				}
			}
		})
	}
	return g.Wait()
}

// Submit enqueues a SignRequest to the worker pool.
func (wp *WorkerPool) Submit(req SignRequest) {
	wp.jobs <- req
}

// QueueDepth returns the current number of pending signing jobs in the queue.
func (wp *WorkerPool) QueueDepth() int {
	return len(wp.jobs)
}
