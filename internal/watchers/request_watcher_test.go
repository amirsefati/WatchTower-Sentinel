package watchers

import "testing"

func TestParseNginxLogLine(t *testing.T) {
	line := `203.0.113.10 - - [20/Apr/2026:14:01:02 +0000] "GET /.env HTTP/1.1" 404 153 "-" "curl/8.7.1"`
	event, err := ParseNginxLogLine(line)
	if err != nil {
		t.Fatalf("ParseNginxLogLine() error = %v", err)
	}
	if event.IP != "203.0.113.10" {
		t.Fatalf("IP = %q, want %q", event.IP, "203.0.113.10")
	}
	if event.Path != "/.env" {
		t.Fatalf("Path = %q, want %q", event.Path, "/.env")
	}
	if event.Status != 404 {
		t.Fatalf("Status = %d, want 404", event.Status)
	}
}
