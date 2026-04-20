package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"watchtower-sentinel/internal/config"
	"watchtower-sentinel/internal/health"
	"watchtower-sentinel/internal/model"
	"watchtower-sentinel/internal/monitors"
	"watchtower-sentinel/internal/notifier"
	"watchtower-sentinel/internal/rules"
	"watchtower-sentinel/internal/state"
	"watchtower-sentinel/internal/watchers"
)

type Service struct {
	cfg             config.Config
	logger          *slog.Logger
	hostname        string
	store           *state.FileStore
	notifier        *notifier.Service
	requestWatcher  *watchers.RequestWatcher
	requestAnalyzer *rules.RequestAnalyzer
	processMonitor  *monitors.ProcessMonitor
	processAnalyzer *rules.ProcessAnalyzer
	resourceMonitor *monitors.ResourceMonitor
	healthServer    *health.Server
}

func New(cfg config.Config, logger *slog.Logger) (*Service, error) {
	store, err := state.NewFileStore(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("read hostname: %w", err)
	}
	tgSender := notifier.NewTelegramSender(cfg)
	return &Service{
		cfg:             cfg,
		logger:          logger,
		hostname:        hostname,
		store:           store,
		notifier:        notifier.NewService(tgSender, store, time.Duration(cfg.AlertCooldownSeconds)*time.Second),
		requestWatcher:  watchers.NewRequestWatcher(cfg.NginxAccessLogPath, cfg.RequestPollInterval),
		requestAnalyzer: rules.NewRequestAnalyzer(cfg.RequestBurstThreshold, time.Duration(cfg.RequestBurstWindowSeconds)*time.Second),
		processMonitor:  monitors.NewProcessMonitor(cfg.HostProcPath, cfg.ProcessScanInterval),
		processAnalyzer: rules.NewProcessAnalyzer(),
		resourceMonitor: monitors.NewResourceMonitor(monitors.NewLinuxProcSampler(cfg.HostProcPath), cfg.CPUThreshold, cfg.RAMThreshold, time.Duration(cfg.ResourceBreachSeconds)*time.Second, cfg.ResourcePollInterval),
		healthServer:    health.New(cfg.ListenAddress, cfg.HealthPath),
	}, nil
}

func (s *Service) Run(ctx context.Context) error {
	requestEvents := make(chan model.RequestEvent, 128)
	processEvents := make(chan model.ProcessEvent, 64)
	resourceEvents := make(chan model.ResourceEvent, 32)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 4)
	var wg sync.WaitGroup

	run := func(name string, fn func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fn(); err != nil {
				select {
				case errCh <- fmt.Errorf("%s: %w", name, err):
				default:
				}
				cancel()
			}
		}()
	}

	run("request watcher", func() error { return s.requestWatcher.Run(ctx, requestEvents) })
	run("process monitor", func() error { return s.processMonitor.Run(ctx, processEvents) })
	run("resource monitor", func() error { return s.resourceMonitor.Run(ctx, resourceEvents) })
	run("health server", func() error { return s.healthServer.Run() })

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case event := <-requestEvents:
				s.handleRequest(ctx, event)
			case event := <-processEvents:
				s.handleProcess(ctx, event)
			case event := <-resourceEvents:
				s.handleResource(ctx, event)
			}
		}
	}()

	<-ctx.Done()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	_ = s.healthServer.Shutdown(shutdownCtx)
	wg.Wait()

	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}

func (s *Service) handleRequest(ctx context.Context, event model.RequestEvent) {
	if s.cfg.NewIPNotifyEnabled {
		if fresh, err := s.store.MarkIPSeen(event.IP, event.OccurredAt); err == nil && fresh {
			alert := model.Alert{
				Key:        fmt.Sprintf("new-ip:%s", event.IP),
				Type:       "NEW_IP",
				Severity:   model.SeverityInfo,
				Reason:     fmt.Sprintf("new client ip observed ip=%s method=%s path=%s", event.IP, event.Method, event.Path),
				OccurredAt: event.OccurredAt,
				Hostname:   s.hostname,
				Labels: map[string]string{
					"ip":     event.IP,
					"method": event.Method,
					"path":   event.Path,
					"status": fmt.Sprintf("%d", event.Status),
				},
			}
			s.sendAlert(ctx, alert)
		}
	}
	for _, alert := range s.requestAnalyzer.Analyze(event) {
		alert.Hostname = s.hostname
		s.sendAlert(ctx, alert)
	}
}

func (s *Service) handleProcess(ctx context.Context, event model.ProcessEvent) {
	alert := s.processAnalyzer.Analyze(event)
	if alert == nil {
		return
	}
	alert.Hostname = s.hostname
	s.sendAlert(ctx, *alert)
}

func (s *Service) handleResource(ctx context.Context, event model.ResourceEvent) {
	alertType := "HIGH_CPU"
	if event.Metric == "ram" {
		alertType = "HIGH_RAM"
	}
	alert := model.Alert{
		Key:        fmt.Sprintf("%s:%s", alertType, s.hostname),
		Type:       alertType,
		Severity:   model.SeverityWarning,
		Reason:     fmt.Sprintf("%s above threshold value=%.2f threshold=%.2f duration=%s", event.Metric, event.Value, event.Threshold, event.Duration.Truncate(time.Second)),
		OccurredAt: event.OccurredAt,
		Hostname:   s.hostname,
		Labels: map[string]string{
			"metric":    event.Metric,
			"value":     fmt.Sprintf("%.2f", event.Value),
			"threshold": fmt.Sprintf("%.2f", event.Threshold),
			"duration":  event.Duration.Truncate(time.Second).String(),
		},
	}
	s.sendAlert(ctx, alert)
}

func (s *Service) sendAlert(ctx context.Context, alert model.Alert) {
	if err := s.notifier.Notify(ctx, alert); err != nil {
		s.logger.Error("failed to send alert", "type", alert.Type, "error", err)
		return
	}
	s.logger.Info("alert sent", "type", alert.Type, "severity", alert.Severity, "reason", alert.Reason)
}
