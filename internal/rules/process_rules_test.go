package rules

import (
	"testing"
	"time"

	"watchtower-sentinel/internal/model"
)

func TestProcessAnalyzerFlagsRiskyBinary(t *testing.T) {
	analyzer := NewProcessAnalyzer()
	event := model.ProcessEvent{
		OccurredAt: time.Now().UTC(),
		PID:        123,
		Name:       "nc",
		Command:    "nc -lvnp 4444",
		Executable: "/usr/bin/nc",
	}
	alert := analyzer.Analyze(event)
	if alert == nil {
		t.Fatal("Analyze() = nil, want alert")
	}
	if alert.Type != "SUSPICIOUS_PROCESS" {
		t.Fatalf("Type = %q, want SUSPICIOUS_PROCESS", alert.Type)
	}
}

func TestProcessAnalyzerFlagsUnexpectedListener(t *testing.T) {
	analyzer := NewProcessAnalyzer()
	event := model.ProcessEvent{
		OccurredAt: time.Now().UTC(),
		PID:        321,
		Name:       "custom-daemon",
		Command:    "/opt/custom-daemon",
		Executable: "/opt/custom-daemon",
		Listening:  true,
		Ports:      []int{4444},
	}
	alert := analyzer.Analyze(event)
	if alert == nil {
		t.Fatal("Analyze() = nil, want listener alert")
	}
}
