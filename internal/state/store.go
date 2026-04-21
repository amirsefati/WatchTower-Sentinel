package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type FileStore struct {
	mu        sync.Mutex
	path      string
	state     persistedState
	saveTimer *time.Timer
}

type persistedState struct {
	SeenIPs    map[string]string `json:"seen_ips"`
	LastAlerts map[string]string `json:"last_alerts"`
}

func NewFileStore(dir string) (*FileStore, error) {
	store := &FileStore{
		path: filepath.Join(dir, "state.json"),
		state: persistedState{
			SeenIPs:    map[string]string{},
			LastAlerts: map[string]string{},
		},
	}

	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *FileStore) MarkIPSeen(ip string, at time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.state.SeenIPs[ip]; exists {
		return false, nil
	}
	s.state.SeenIPs[ip] = at.UTC().Format(time.RFC3339)
	return true, s.persistLocked()
}

func (s *FileStore) SeenIP(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, exists := s.state.SeenIPs[ip]
	return exists
}

func (s *FileStore) LastAlert(key string) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	value, ok := s.state.LastAlerts[key]
	if !ok {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, false
	}
	return parsed, true
}

func (s *FileStore) RecordAlert(key string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.LastAlerts[key] = at.UTC().Format(time.RFC3339)
	return s.persistLocked()
}

func (s *FileStore) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read state file: %w", err)
	}
	if err := json.Unmarshal(data, &s.state); err != nil {
		return fmt.Errorf("unmarshal state file: %w", err)
	}
	if s.state.SeenIPs == nil {
		s.state.SeenIPs = map[string]string{}
	}
	if s.state.LastAlerts == nil {
		s.state.LastAlerts = map[string]string{}
	}
	return nil
}

func (s *FileStore) persistLocked() error {
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("write temp state: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("rename state file: %w", err)
	}
	return nil
}
