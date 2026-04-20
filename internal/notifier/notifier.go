package notifier

import (
	"context"
	"fmt"
	"time"

	"watchtower-sentinel/internal/model"
	"watchtower-sentinel/internal/state"
)

type Sender interface {
	Send(ctx context.Context, alert model.Alert) error
}

type Service struct {
	sender   Sender
	store    *state.FileStore
	cooldown time.Duration
}

func NewService(sender Sender, store *state.FileStore, cooldown time.Duration) *Service {
	return &Service{sender: sender, store: store, cooldown: cooldown}
}

func (s *Service) Notify(ctx context.Context, alert model.Alert) error {
	if alert.OccurredAt.IsZero() {
		alert.OccurredAt = time.Now().UTC()
	}
	if alert.Key == "" {
		return fmt.Errorf("alert key is required")
	}
	if last, ok := s.store.LastAlert(alert.Key); ok && alert.OccurredAt.Sub(last) < s.cooldown {
		return nil
	}
	if err := s.sender.Send(ctx, alert); err != nil {
		return err
	}
	return s.store.RecordAlert(alert.Key, alert.OccurredAt)
}
