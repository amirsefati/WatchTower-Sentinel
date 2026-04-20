package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"watchtower-sentinel/internal/config"
	"watchtower-sentinel/internal/model"
)

type TelegramSender struct {
	client *http.Client
	cfg    config.Config
}

func NewTelegramSender(cfg config.Config) *TelegramSender {
	return &TelegramSender{
		client: &http.Client{Timeout: 10 * time.Second},
		cfg:    cfg,
	}
}

func (t *TelegramSender) Send(ctx context.Context, alert model.Alert) error {
	payload := map[string]any{
		"chat_id":    t.cfg.TelegramChatID,
		"text":       t.formatMessage(alert),
		"parse_mode": "Markdown",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal telegram payload: %w", err)
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.cfg.TelegramBotToken)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create telegram request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("send telegram request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("telegram returned status %d", resp.StatusCode)
	}
	return nil
}

func (t *TelegramSender) formatMessage(alert model.Alert) string {
	var details []string
	keys := make([]string, 0, len(alert.Labels))
	for key := range alert.Labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		details = append(details, fmt.Sprintf("%s=%s", key, alert.Labels[key]))
	}

	base := fmt.Sprintf("[%s/%s] %s\nseverity=%s host=%s time=%s\n%s",
		escapeMarkdown(t.cfg.ServerLocation),
		escapeMarkdown(t.cfg.ServerName),
		escapeMarkdown(alert.Type),
		escapeMarkdown(string(alert.Severity)),
		escapeMarkdown(alert.Hostname),
		escapeMarkdown(alert.OccurredAt.In(resolveLocation(t.cfg.TimeZone)).Format(time.RFC3339)),
		escapeMarkdown(alert.Reason),
	)
	if len(details) == 0 {
		return base
	}
	return base + "\n" + escapeMarkdown(strings.Join(details, " "))
}

func resolveLocation(name string) *time.Location {
	loc, err := time.LoadLocation(name)
	if err != nil {
		return time.UTC
	}
	return loc
}

func escapeMarkdown(input string) string {
	replacer := strings.NewReplacer(
		"_", "\\_",
		"*", "\\*",
		"[", "\\[",
		"`", "\\`",
	)
	return replacer.Replace(input)
}
