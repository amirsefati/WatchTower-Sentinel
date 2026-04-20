package rules

import (
	"fmt"
	"path"
	"strings"
	"sync"
	"time"

	"watchtower-sentinel/internal/model"
)

var sensitivePaths = []string{
	"/.env",
	"/wp-admin",
	"/wp-login.php",
	"/phpmyadmin",
	"/admin",
	"/vendor/phpunit",
	"/.git/config",
}

type RequestAnalyzer struct {
	mu             sync.Mutex
	hits           map[string][]time.Time
	burstThreshold int
	burstWindow    time.Duration
}

func NewRequestAnalyzer(threshold int, window time.Duration) *RequestAnalyzer {
	return &RequestAnalyzer{
		hits:           map[string][]time.Time{},
		burstThreshold: threshold,
		burstWindow:    window,
	}
}

func (r *RequestAnalyzer) Analyze(event model.RequestEvent) []model.Alert {
	r.mu.Lock()
	defer r.mu.Unlock()

	var alerts []model.Alert
	now := event.OccurredAt

	r.hits[event.IP] = append(r.hits[event.IP], now)
	cutoff := now.Add(-r.burstWindow)
	filtered := r.hits[event.IP][:0]
	for _, hit := range r.hits[event.IP] {
		if !hit.Before(cutoff) {
			filtered = append(filtered, hit)
		}
	}
	r.hits[event.IP] = filtered

	if len(filtered) >= r.burstThreshold {
		alerts = append(alerts, model.Alert{
			Key:        fmt.Sprintf("burst:%s", event.IP),
			Type:       "REQUEST_BURST",
			Severity:   model.SeverityWarning,
			Reason:     fmt.Sprintf("request burst detected from ip=%s count=%d window=%s", event.IP, len(filtered), r.burstWindow),
			OccurredAt: now,
			Labels: map[string]string{
				"ip":     event.IP,
				"count":  fmt.Sprintf("%d", len(filtered)),
				"window": r.burstWindow.String(),
			},
		})
	}

	normalizedPath := strings.ToLower(path.Clean("/" + strings.TrimPrefix(event.Path, "/")))
	for _, sensitive := range sensitivePaths {
		if normalizedPath == sensitive || strings.HasPrefix(normalizedPath, sensitive+"/") {
			alerts = append(alerts, model.Alert{
				Key:        fmt.Sprintf("sensitive:%s:%s", event.IP, sensitive),
				Type:       "SENSITIVE_PATH_SCAN",
				Severity:   model.SeverityWarning,
				Reason:     fmt.Sprintf("sensitive path probe detected ip=%s path=%s", event.IP, event.Path),
				OccurredAt: now,
				Labels: map[string]string{
					"ip":     event.IP,
					"path":   event.Path,
					"method": event.Method,
					"status": fmt.Sprintf("%d", event.Status),
				},
			})
			break
		}
	}

	if event.Status == 401 || event.Status == 403 {
		if strings.Contains(normalizedPath, "/login") || strings.Contains(normalizedPath, "/auth") {
			alerts = append(alerts, model.Alert{
				Key:        fmt.Sprintf("auth:%s:%s", event.IP, normalizedPath),
				Type:       "AUTH_PROBE",
				Severity:   model.SeverityWarning,
				Reason:     fmt.Sprintf("authentication probe detected ip=%s path=%s status=%d", event.IP, event.Path, event.Status),
				OccurredAt: now,
				Labels: map[string]string{
					"ip":     event.IP,
					"path":   event.Path,
					"status": fmt.Sprintf("%d", event.Status),
				},
			})
		}
	}

	return alerts
}
