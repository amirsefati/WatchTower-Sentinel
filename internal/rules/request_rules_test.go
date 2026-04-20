package rules

import (
	"testing"
	"time"

	"watchtower-sentinel/internal/model"
)

func TestRequestAnalyzerFlagsSensitivePath(t *testing.T) {
	analyzer := NewRequestAnalyzer(100, 10*time.Second)
	event := model.RequestEvent{
		OccurredAt: time.Now().UTC(),
		IP:         "1.2.3.4",
		Method:     "GET",
		Path:       "/.env",
		Status:     404,
	}
	alerts := analyzer.Analyze(event)
	if len(alerts) == 0 {
		t.Fatal("Analyze() returned no alerts")
	}
}
