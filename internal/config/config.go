package config

import (
	"bufio"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ServerName                string
	ServerLocation            string
	TelegramBotToken          string
	TelegramChatID            string
	NginxAccessLogPath        string
	StateDir                  string
	TimeZone                  string
	ProcessAlertPolicy        string
	HostProcPath              string
	ListenAddress             string
	HealthPath                string
	CPUThreshold              float64
	RAMThreshold              float64
	ResourceBreachSeconds     int
	RequestBurstThreshold     int
	RequestBurstWindowSeconds int
	AlertCooldownSeconds      int
	ProcessScanInterval       time.Duration
	RequestPollInterval       time.Duration
	ResourcePollInterval      time.Duration
	NewIPNotifyEnabled        bool
	LogLevel                  slog.Level
}

func Load() (Config, error) {
	_ = loadDotEnv(".env")

	cfg := Config{
		ServerName:                getenv("SERVER_NAME", ""),
		ServerLocation:            getenv("SERVER_LOCATION", ""),
		TelegramBotToken:          getenv("TELEGRAM_BOT_TOKEN", ""),
		TelegramChatID:            getenv("TELEGRAM_CHAT_ID", ""),
		NginxAccessLogPath:        getenv("NGINX_ACCESS_LOG_PATH", "/var/log/nginx/access.log"),
		StateDir:                  getenv("STATE_DIR", "./state"),
		TimeZone:                  getenv("TIMEZONE", "UTC"),
		ProcessAlertPolicy:        strings.ToLower(getenv("PROCESS_ALERT_POLICY", "risk-based")),
		HostProcPath:              getenv("HOST_PROC_PATH", "/proc"),
		ListenAddress:             getenv("LISTEN_ADDRESS", ":8081"),
		HealthPath:                getenv("HEALTH_PATH", "/healthz"),
		CPUThreshold:              mustFloat("CPU_THRESHOLD", 90),
		RAMThreshold:              mustFloat("RAM_THRESHOLD", 90),
		ResourceBreachSeconds:     mustInt("RESOURCE_BREACH_SECONDS", 10),
		RequestBurstThreshold:     mustInt("REQUEST_BURST_THRESHOLD", 100),
		RequestBurstWindowSeconds: mustInt("REQUEST_BURST_WINDOW_SECONDS", 10),
		AlertCooldownSeconds:      mustInt("ALERT_COOLDOWN_SECONDS", 300),
		ProcessScanInterval:       mustDurationSeconds("PROCESS_SCAN_INTERVAL_SECONDS", 5),
		RequestPollInterval:       mustDurationSeconds("REQUEST_POLL_INTERVAL_SECONDS", 1),
		ResourcePollInterval:      mustDurationSeconds("RESOURCE_POLL_INTERVAL_SECONDS", 2),
		NewIPNotifyEnabled:        mustBool("NEW_IP_NOTIFY_ENABLED", true),
		LogLevel:                  parseLogLevel(getenv("LOG_LEVEL", "INFO")),
	}

	if err := ensureRequired(cfg); err != nil {
		return Config{}, err
	}
	if cfg.ProcessAlertPolicy != "risk-based" {
		return Config{}, fmt.Errorf("unsupported PROCESS_ALERT_POLICY: %s", cfg.ProcessAlertPolicy)
	}
	if cfg.ResourceBreachSeconds <= 0 {
		return Config{}, errors.New("RESOURCE_BREACH_SECONDS must be greater than zero")
	}
	if cfg.RequestBurstThreshold <= 0 {
		return Config{}, errors.New("REQUEST_BURST_THRESHOLD must be greater than zero")
	}
	if cfg.RequestBurstWindowSeconds <= 0 {
		return Config{}, errors.New("REQUEST_BURST_WINDOW_SECONDS must be greater than zero")
	}
	if err := os.MkdirAll(cfg.StateDir, 0o755); err != nil {
		return Config{}, fmt.Errorf("create state dir: %w", err)
	}
	cfg.StateDir = filepath.Clean(cfg.StateDir)
	return cfg, nil
}

func ensureRequired(cfg Config) error {
	var missing []string
	for key, value := range map[string]string{
		"SERVER_NAME":           cfg.ServerName,
		"SERVER_LOCATION":       cfg.ServerLocation,
		"TELEGRAM_BOT_TOKEN":    cfg.TelegramBotToken,
		"TELEGRAM_CHAT_ID":      cfg.TelegramChatID,
		"NGINX_ACCESS_LOG_PATH": cfg.NginxAccessLogPath,
	} {
		if strings.TrimSpace(value) == "" {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required env vars: %s", strings.Join(missing, ", "))
	}
	return nil
}

func getenv(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func mustFloat(key string, fallback float64) float64 {
	value := getenv(key, "")
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

func mustInt(key string, fallback int) int {
	value := getenv(key, "")
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func mustBool(key string, fallback bool) bool {
	value := getenv(key, "")
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func mustDurationSeconds(key string, fallback int) time.Duration {
	return time.Duration(mustInt(key, fallback)) * time.Second
}

func parseLogLevel(level string) slog.Level {
	switch strings.ToUpper(strings.TrimSpace(level)) {
	case "DEBUG":
		return slog.LevelDebug
	case "WARN":
		return slog.LevelWarn
	case "ERROR":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func loadDotEnv(path string) error {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		if key == "" {
			continue
		}
		if _, exists := os.LookupEnv(key); !exists {
			_ = os.Setenv(key, value)
		}
	}
	return scanner.Err()
}
