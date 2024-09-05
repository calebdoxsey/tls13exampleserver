package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
)

var logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
	AddSource: false,
	Level:     slog.LevelDebug,
}))

func main() {
	slog.SetDefault(logger)

	err := run(context.Background())
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	bindAddr := ":8443"
	if p, ok := os.LookupEnv("PORT"); ok {
		bindAddr = ":" + p
	}

	tlsCfg, err := getTLSConfig(ctx)
	if err != nil {
		return err
	}

	logger.InfoContext(ctx, "starting TLS v1.3 server", "bind-addr", bindAddr)
	li, err := tls.Listen("tcp", bindAddr, tlsCfg)
	if err != nil {
		return fmt.Errorf("error starting TLS listener: %w", err)
	}
	defer li.Close()

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "HELLO WORLD\n")
		}),
	}

	err = srv.Serve(li)
	if err != nil {
		return fmt.Errorf("error serving HTTP server: %w", err)
	}

	return nil
}
