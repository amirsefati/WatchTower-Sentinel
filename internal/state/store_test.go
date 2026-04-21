package state

import (
	"testing"
	"time"
)

func TestFileStorePersistsSeenIPs(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	if err != nil {
		t.Fatalf("NewFileStore() error = %v", err)
	}
	now := time.Now().UTC()
	fresh, err := store.MarkIPSeen("1.2.3.4", now)
	if err != nil {
		t.Fatalf("MarkIPSeen() error = %v", err)
	}
	if !fresh {
		t.Fatalf("MarkIPSeen() fresh = false, want true")
	}

	reloaded, err := NewFileStore(dir)
	if err != nil {
		t.Fatalf("NewFileStore() reload error = %v", err)
	}
	if !reloaded.SeenIP("1.2.3.4") {
		t.Fatalf("SeenIP() = false, want true after reload")
	}
}
