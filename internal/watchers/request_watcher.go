package watchers

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"watchtower-sentinel/internal/model"
)

var nginxLogPattern = regexp.MustCompile(`^(\S+) \S+ \S+ \[([^\]]+)\] "([A-Z]+) ([^"]+?) [^"]+" (\d{3}) \S+ "[^"]*" "([^"]*)"`)

type RequestWatcher struct {
	path         string
	pollInterval time.Duration
	lastOffset   int64
}

func NewRequestWatcher(path string, pollInterval time.Duration) *RequestWatcher {
	return &RequestWatcher{path: path, pollInterval: pollInterval}
}

func (w *RequestWatcher) Run(ctx context.Context, out chan<- model.RequestEvent) error {
	ticker := time.NewTicker(w.pollInterval)
	defer ticker.Stop()

	for {
		if err := w.readNewLines(out); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (w *RequestWatcher) readNewLines(out chan<- model.RequestEvent) error {
	file, err := os.Open(w.path)
	if err != nil {
		return fmt.Errorf("open nginx access log: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat nginx access log: %w", err)
	}
	if info.Size() < w.lastOffset {
		w.lastOffset = 0
	}

	if _, err := file.Seek(w.lastOffset, io.SeekStart); err != nil {
		return fmt.Errorf("seek nginx access log: %w", err)
	}
	reader := bufio.NewScanner(file)
	for reader.Scan() {
		line := reader.Text()
		event, err := ParseNginxLogLine(line)
		if err == nil {
			out <- event
		}
	}
	if err := reader.Err(); err != nil {
		return fmt.Errorf("scan nginx access log: %w", err)
	}
	offset, err := file.Seek(0, io.SeekCurrent)
	if err != nil {
		return fmt.Errorf("capture nginx access log offset: %w", err)
	}
	w.lastOffset = offset
	return nil
}

func ParseNginxLogLine(line string) (model.RequestEvent, error) {
	matches := nginxLogPattern.FindStringSubmatch(line)
	if len(matches) != 7 {
		return model.RequestEvent{}, fmt.Errorf("unsupported nginx log format")
	}
	status, err := strconv.Atoi(matches[5])
	if err != nil {
		return model.RequestEvent{}, fmt.Errorf("parse status: %w", err)
	}
	occurredAt, err := time.Parse("02/Jan/2006:15:04:05 -0700", matches[2])
	if err != nil {
		return model.RequestEvent{}, fmt.Errorf("parse time: %w", err)
	}
	requestPath := matches[4]
	if space := strings.IndexByte(requestPath, ' '); space > 0 {
		requestPath = requestPath[:space]
	}
	return model.RequestEvent{
		OccurredAt: occurredAt.UTC(),
		IP:         matches[1],
		Method:     matches[3],
		Path:       requestPath,
		Status:     status,
		UserAgent:  matches[6],
		Raw:        line,
	}, nil
}
