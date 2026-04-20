package monitors

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"watchtower-sentinel/internal/model"
)

type ResourceSampler interface {
	Sample() (cpu float64, ram float64, err error)
}

type ResourceMonitor struct {
	sampler        ResourceSampler
	cpuThreshold   float64
	ramThreshold   float64
	breachDuration time.Duration
	pollInterval   time.Duration
	cpuBreachStart time.Time
	ramBreachStart time.Time
	cpuAlertActive bool
	ramAlertActive bool
}

func NewResourceMonitor(sampler ResourceSampler, cpuThreshold, ramThreshold float64, breachDuration, pollInterval time.Duration) *ResourceMonitor {
	return &ResourceMonitor{
		sampler:        sampler,
		cpuThreshold:   cpuThreshold,
		ramThreshold:   ramThreshold,
		breachDuration: breachDuration,
		pollInterval:   pollInterval,
	}
}

func (m *ResourceMonitor) Run(ctx context.Context, out chan<- model.ResourceEvent) error {
	ticker := time.NewTicker(m.pollInterval)
	defer ticker.Stop()

	for {
		cpu, ram, err := m.sampler.Sample()
		if err == nil {
			if event, ok := m.evaluate("cpu", cpu, m.cpuThreshold, &m.cpuBreachStart, &m.cpuAlertActive); ok {
				out <- event
			}
			if event, ok := m.evaluate("ram", ram, m.ramThreshold, &m.ramBreachStart, &m.ramAlertActive); ok {
				out <- event
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (m *ResourceMonitor) evaluate(metric string, value, threshold float64, breachStart *time.Time, active *bool) (model.ResourceEvent, bool) {
	now := time.Now().UTC()
	if value < threshold {
		*breachStart = time.Time{}
		*active = false
		return model.ResourceEvent{}, false
	}
	if breachStart.IsZero() {
		*breachStart = now
		return model.ResourceEvent{}, false
	}
	if !*active && now.Sub(*breachStart) >= m.breachDuration {
		*active = true
		return model.ResourceEvent{
			OccurredAt: now,
			Metric:     metric,
			Value:      value,
			Threshold:  threshold,
			Duration:   now.Sub(*breachStart),
		}, true
	}
	return model.ResourceEvent{}, false
}

type LinuxProcSampler struct {
	procPath   string
	prevCPU    cpuSnapshot
	prevHasCPU bool
}

type cpuSnapshot struct {
	idle  uint64
	total uint64
}

func NewLinuxProcSampler(procPath string) *LinuxProcSampler {
	return &LinuxProcSampler{procPath: procPath}
}

func (s *LinuxProcSampler) Sample() (float64, float64, error) {
	cpu, err := s.sampleCPU()
	if err != nil {
		return 0, 0, err
	}
	ram, err := s.sampleRAM()
	if err != nil {
		return 0, 0, err
	}
	return cpu, ram, nil
}

func (s *LinuxProcSampler) sampleCPU() (float64, error) {
	data, err := os.ReadFile(filepath.Join(s.procPath, "stat"))
	if err != nil {
		return 0, fmt.Errorf("read /proc/stat: %w", err)
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) == 0 {
		return 0, fmt.Errorf("empty /proc/stat")
	}
	fields := strings.Fields(lines[0])
	if len(fields) < 5 {
		return 0, fmt.Errorf("invalid cpu line in /proc/stat")
	}

	var total uint64
	for _, field := range fields[1:] {
		value, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parse cpu field: %w", err)
		}
		total += value
	}
	idle, err := strconv.ParseUint(fields[4], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse cpu idle: %w", err)
	}
	snapshot := cpuSnapshot{idle: idle, total: total}
	if !s.prevHasCPU {
		s.prevCPU = snapshot
		s.prevHasCPU = true
		return 0, nil
	}

	deltaTotal := snapshot.total - s.prevCPU.total
	deltaIdle := snapshot.idle - s.prevCPU.idle
	s.prevCPU = snapshot
	if deltaTotal == 0 {
		return 0, nil
	}
	return 100 * (1 - float64(deltaIdle)/float64(deltaTotal)), nil
}

func (s *LinuxProcSampler) sampleRAM() (float64, error) {
	data, err := os.ReadFile(filepath.Join(s.procPath, "meminfo"))
	if err != nil {
		return 0, fmt.Errorf("read /proc/meminfo: %w", err)
	}
	values := map[string]float64{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		value, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			continue
		}
		values[strings.TrimSuffix(fields[0], ":")] = value
	}
	total := values["MemTotal"]
	available := values["MemAvailable"]
	if total == 0 {
		return 0, fmt.Errorf("MemTotal missing from /proc/meminfo")
	}
	used := total - available
	return (used / total) * 100, nil
}
