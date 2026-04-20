package notifier

import (
	"context"
	"testing"
	"time"

	"watchtower-sentinel/internal/model"
	"watchtower-sentinel/internal/state"
)

type fakeSender struct {
	sent []model.Alert
}

func (f *fakeSender) Send(_ context.Context, alert model.Alert) error {
	f.sent = append(f.sent, alert)
	return nil
}

func TestNotifierDeduplicatesByCooldown(t *testing.T) {
	store, err := state.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileStore() error = %v", err)
	}
	sender := &fakeSender{}
	service := NewService(sender, store, 5*time.Minute)

	base := time.Now().UTC()
	alert := model.Alert{
		Key:        "dup-key",
		Type:       "NEW_IP",
		Severity:   model.SeverityInfo,
		Reason:     "first",
		OccurredAt: base,
	}
	if err := service.Notify(context.Background(), alert); err != nil {
		t.Fatalf("Notify() first error = %v", err)
	}
	if err := service.Notify(context.Background(), alert); err != nil {
		t.Fatalf("Notify() second error = %v", err)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("sent count = %d, want 1", len(sender.sent))
	}
}
