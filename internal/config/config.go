package config

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"

	"llmgw/internal/domain"
)

func DataDir() string {
	if p := os.Getenv("LLMGW_DATA_DIR"); p != "" {
		return p
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "./data"
	}
	return filepath.Join(h, "Library", "Application Support", "LLMGateway")
}
func Validate(s domain.Settings) error {
	_, port, err := net.SplitHostPort(s.ListenAddress)
	if err != nil {
		return errors.New("listen_address must be host:port")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return errors.New("invalid listen port")
	}
	if s.HealthIntervalSeconds < 1 || s.HealthIntervalSeconds > 86400 {
		return errors.New("health interval must be 1–86400 seconds")
	}
	if s.RequestTimeoutSeconds < 1 || s.RequestTimeoutSeconds > 86400 {
		return errors.New("request timeout must be 1–86400 seconds")
	}
	if s.LogRotationBytes < 1024 || s.LogRotationBytes > 1<<40 {
		return errors.New("log rotation size must be 1024 bytes–1 TiB")
	}
	if s.LogGenerations < 1 || s.LogGenerations > 100 {
		return errors.New("log generations must be 1–100")
	}
	if s.StatisticsRetentionDays < 1 || s.StatisticsRetentionDays > 36500 || s.BackupRetentionDays < 1 || s.BackupRetentionDays > 36500 {
		return errors.New("retention days must be 1–36500")
	}
	return nil
}
