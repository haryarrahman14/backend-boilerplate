// Command api runs the HTTP server (`api`) or the database migrations (`api migrate [up|down|status]`).
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"

	"boilerplate/internal/features/auth"
	"boilerplate/internal/features/files"
	"boilerplate/internal/features/health"
	"boilerplate/internal/features/users"
	"boilerplate/internal/platform/config"
	"boilerplate/internal/platform/db"
	"boilerplate/internal/platform/httpx"
	"boilerplate/internal/platform/mailer"
	"boilerplate/internal/platform/ratelimit"
	"boilerplate/internal/platform/storage"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(log)

	var err error
	if len(os.Args) > 1 && os.Args[1] == "migrate" {
		err = migrate(os.Args[2:])
	} else {
		err = serve(log)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func migrate(args []string) error {
	url, err := config.LoadDatabaseURL()
	if err != nil {
		return err
	}
	command := "up"
	if len(args) > 0 {
		command = args[0]
	}
	return db.Migrate(context.Background(), url, command)
}

func serve(log *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := db.Open(ctx, cfg.DatabaseURL.Reveal())
	if err != nil {
		return err
	}
	defer pool.Close()

	if cfg.SMTPHost == "" {
		log.Warn("SMTP_HOST is empty (development only): emails, including their one-time links, are written to the log instead of sent")
	}
	mail := mailer.New(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUser, cfg.SMTPPass.Reveal(), cfg.MailFrom, cfg.Production())
	store := storage.New(cfg.S3Endpoint, cfg.S3Region, cfg.S3AccessKeyID, cfg.S3SecretAccessKey.Reveal(), cfg.S3Bucket)
	authSvc, err := auth.NewService(cfg, pool, mail)
	if err != nil {
		return err
	}

	r := chi.NewRouter()
	r.Use(
		httpx.RequestContext(log, cfg.TrustedProxyHops, cfg.TrustedProxyCIDRs),
		httpx.SecurityHeaders(cfg.Production(), 30*time.Second),
		httpx.CORS(cfg.CORSOrigins),
	)
	r.NotFound(func(w http.ResponseWriter, r *http.Request) { httpx.WriteError(w, r, httpx.NotFound()) })
	// A known path with the wrong method is reported as an unknown route; SPEC has no 405 code.
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) { httpx.WriteError(w, r, httpx.NotFound()) })

	health.Routes(r, pool, !cfg.Production())
	r.Route("/api/v1", func(r chi.Router) {
		authSvc.Routes(r, ratelimit.New(cfg.RateLimitAuthPerMinute, time.Minute).Middleware)
		users.New(pool, store, authSvc).Routes(r)
		files.New(cfg, pool, store).Routes(r, authSvc.Require)
	})

	srv := &http.Server{
		Addr:              ":" + strconv.Itoa(cfg.Port),
		Handler:           r,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      35 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	errCh := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", srv.Addr, "env", cfg.AppEnv)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("shutdown", "error", err.Error())
	}
	authSvc.Wait(shutdownCtx) // let queued emails finish before the pool closes
	log.Info("stopped")
	return nil
}
