package model

import "time"

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

type Alert struct {
	Key        string            `json:"key"`
	Type       string            `json:"type"`
	Severity   Severity          `json:"severity"`
	Reason     string            `json:"reason"`
	OccurredAt time.Time         `json:"occurred_at"`
	Hostname   string            `json:"hostname"`
	Labels     map[string]string `json:"labels,omitempty"`
}

type RequestEvent struct {
	OccurredAt time.Time
	IP         string
	Method     string
	Path       string
	Status     int
	UserAgent  string
	Raw        string
}

type ProcessEvent struct {
	OccurredAt time.Time
	PID        int
	Name       string
	Command    string
	Executable string
	Reason     string
	Listening  bool
	Ports      []int
}

type ResourceEvent struct {
	OccurredAt time.Time
	Metric     string
	Value      float64
	Threshold  float64
	Duration   time.Duration
}
