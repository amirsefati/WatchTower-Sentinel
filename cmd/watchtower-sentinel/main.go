package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"watchtower-sentinel/internal/app"
	"watchtower-sentinel/internal/config"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: cfg.LogLevel,
	}))
	slog.SetDefault(logger)

	service, err := app.New(cfg, logger)
	if err != nil {
		logger.Error("failed to initialize service", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Info("watchtower sentinel starting", "listen_address", cfg.ListenAddress)
	if err := service.Run(ctx); err != nil && ctx.Err() == nil {
		logger.Error("watchtower sentinel stopped with error", "error", err)
		os.Exit(1)
	}
	logger.Info("watchtower sentinel stopped")
}
