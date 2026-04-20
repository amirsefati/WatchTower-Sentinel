package monitors

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"watchtower-sentinel/internal/model"
)

type ProcessMonitor struct {
	procPath     string
	pollInterval time.Duration
	seen         map[int]struct{}
}

func NewProcessMonitor(procPath string, pollInterval time.Duration) *ProcessMonitor {
	return &ProcessMonitor{
		procPath:     procPath,
		pollInterval: pollInterval,
		seen:         map[int]struct{}{},
	}
}

func (m *ProcessMonitor) Run(ctx context.Context, out chan<- model.ProcessEvent) error {
	ticker := time.NewTicker(m.pollInterval)
	defer ticker.Stop()

	if err := m.seed(); err != nil {
		return err
	}

	for {
		events, err := m.scan()
		if err == nil {
			for _, event := range events {
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

func (m *ProcessMonitor) seed() error {
	entries, err := os.ReadDir(m.procPath)
	if err != nil {
		return fmt.Errorf("read proc dir: %w", err)
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err == nil {
			m.seen[pid] = struct{}{}
		}
	}
	return nil
}

func (m *ProcessMonitor) scan() ([]model.ProcessEvent, error) {
	entries, err := os.ReadDir(m.procPath)
	if err != nil {
		return nil, fmt.Errorf("scan proc dir: %w", err)
	}
	listeners, err := m.loadListeningSocketInodes()
	if err != nil {
		return nil, err
	}
	var events []model.ProcessEvent
	current := map[int]struct{}{}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		current[pid] = struct{}{}
		if _, exists := m.seen[pid]; exists {
			continue
		}
		m.seen[pid] = struct{}{}
		event, err := m.readProcess(pid, listeners)
		if err == nil {
			events = append(events, event)
		}
	}
	for pid := range m.seen {
		if _, ok := current[pid]; !ok {
			delete(m.seen, pid)
		}
	}
	return events, nil
}

func (m *ProcessMonitor) readProcess(pid int, listeners map[string]int) (model.ProcessEvent, error) {
	base := filepath.Join(m.procPath, strconv.Itoa(pid))
	comm, err := os.ReadFile(filepath.Join(base, "comm"))
	if err != nil {
		return model.ProcessEvent{}, err
	}
	cmdlineRaw, _ := os.ReadFile(filepath.Join(base, "cmdline"))
	command := strings.ReplaceAll(string(cmdlineRaw), "\x00", " ")
	command = strings.TrimSpace(command)
	exe, _ := os.Readlink(filepath.Join(base, "exe"))
	listening, ports := m.readProcessSockets(base, listeners)
	return model.ProcessEvent{
		OccurredAt: time.Now().UTC(),
		PID:        pid,
		Name:       strings.TrimSpace(string(comm)),
		Command:    command,
		Executable: exe,
		Listening:  listening,
		Ports:      ports,
	}, nil
}

func (m *ProcessMonitor) readProcessSockets(base string, listeners map[string]int) (bool, []int) {
	fdDir := filepath.Join(base, "fd")
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return false, nil
	}
	portSet := map[int]struct{}{}
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join(fdDir, entry.Name()))
		if err != nil {
			continue
		}
		inode, ok := socketInodeFromLink(target)
		if !ok {
			continue
		}
		if port, exists := listeners[inode]; exists {
			portSet[port] = struct{}{}
		}
	}
	if len(portSet) == 0 {
		return false, nil
	}
	ports := make([]int, 0, len(portSet))
	for port := range portSet {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return true, ports
}

func (m *ProcessMonitor) loadListeningSocketInodes() (map[string]int, error) {
	result := map[string]int{}
	for _, name := range []string{"tcp", "tcp6"} {
		if err := readListeningSocketTable(filepath.Join(m.procPath, "net", name), result); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func readListeningSocketTable(path string, out map[string]int) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	first := true
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if first {
			first = false
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		if fields[3] != "0A" {
			continue
		}
		port, err := decodeHexPort(fields[1])
		if err != nil {
			continue
		}
		out[fields[9]] = port
	}
	return scanner.Err()
}

func decodeHexPort(localAddress string) (int, error) {
	_, portHex, ok := strings.Cut(localAddress, ":")
	if !ok {
		return 0, fmt.Errorf("invalid local address")
	}
	value, err := strconv.ParseInt(portHex, 16, 64)
	if err != nil {
		return 0, err
	}
	return int(value), nil
}

func socketInodeFromLink(link string) (string, bool) {
	if !strings.HasPrefix(link, "socket:[") || !strings.HasSuffix(link, "]") {
		return "", false
	}
	return strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]"), true
}
