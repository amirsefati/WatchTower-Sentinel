package rules

import (
	"fmt"
	"path/filepath"
	"strings"

	"watchtower-sentinel/internal/model"
)

var riskyNames = map[string]struct{}{
	"nc":      {},
	"ncat":    {},
	"netcat":  {},
	"socat":   {},
	"masscan": {},
	"nmap":    {},
	"xmrig":   {},
	"hydra":   {},
}

type ProcessAnalyzer struct{}

func NewProcessAnalyzer() *ProcessAnalyzer {
	return &ProcessAnalyzer{}
}

func (p *ProcessAnalyzer) Analyze(event model.ProcessEvent) *model.Alert {
	name := strings.ToLower(event.Name)
	command := strings.ToLower(event.Command)
	execPath := strings.ToLower(event.Executable)

	if _, ok := riskyNames[name]; ok {
		return buildProcessAlert(event, model.SeverityCritical, "risky tool execution detected")
	}
	if strings.HasPrefix(execPath, "/tmp/") || strings.HasPrefix(execPath, "/var/tmp/") || strings.HasPrefix(execPath, "/dev/shm/") {
		return buildProcessAlert(event, model.SeverityCritical, "process executed from temporary path")
	}
	if strings.Contains(command, "curl ") && strings.Contains(command, "| sh") {
		return buildProcessAlert(event, model.SeverityCritical, "curl pipe-to-shell pattern detected")
	}
	if strings.Contains(command, "wget ") && strings.Contains(command, "sh ") {
		return buildProcessAlert(event, model.SeverityCritical, "wget shell execution pattern detected")
	}
	if event.Listening && !isCommonSystemBinary(execPath) {
		return buildProcessAlert(event, model.SeverityWarning, "unexpected listener-like process detected")
	}
	return nil
}

func buildProcessAlert(event model.ProcessEvent, severity model.Severity, reason string) *model.Alert {
	keyName := event.Executable
	if keyName == "" {
		keyName = event.Name
	}
	return &model.Alert{
		Key:        fmt.Sprintf("proc:%s:%s", reason, filepath.Base(keyName)),
		Type:       "SUSPICIOUS_PROCESS",
		Severity:   severity,
		Reason:     fmt.Sprintf("%s pid=%d name=%s", reason, event.PID, event.Name),
		OccurredAt: event.OccurredAt,
		Labels: map[string]string{
			"pid":     fmt.Sprintf("%d", event.PID),
			"name":    event.Name,
			"command": event.Command,
			"exe":     event.Executable,
			"ports":   formatPorts(event.Ports),
		},
	}
}

func isCommonSystemBinary(execPath string) bool {
	return strings.HasPrefix(execPath, "/usr/sbin/") ||
		strings.HasPrefix(execPath, "/usr/bin/") ||
		strings.HasPrefix(execPath, "/bin/") ||
		strings.HasPrefix(execPath, "/sbin/")
}

func formatPorts(ports []int) string {
	if len(ports) == 0 {
		return ""
	}
	values := make([]string, 0, len(ports))
	for _, port := range ports {
		values = append(values, fmt.Sprintf("%d", port))
	}
	return strings.Join(values, ",")
}
