package domain

// Secret ciphertexts and password hashes are never serialized into administrative responses.
type Engine struct {
	ID           string  `json:"id"`
	Name         string  `json:"name"`
	BaseURL      string  `json:"base_url"`
	Type         string  `json:"type"`
	DetectedType string  `json:"detected_type"`
	AuthType     string  `json:"auth_type"`
	SecretCipher []byte  `json:"-"`
	HasSecret    bool    `json:"has_secret"`
	Enabled      bool    `json:"enabled"`
	Status       string  `json:"status"`
	LastCheck    string  `json:"last_check"`
	LastSuccess  string  `json:"last_success"`
	LastError    string  `json:"last_error"`
	LatencyMS    float64 `json:"latency_ms"`
	CreatedAt    string  `json:"created_at"`
	UpdatedAt    string  `json:"updated_at"`
}
type UpstreamModel struct {
	EngineID     string          `json:"engine_id"`
	UpstreamID   string          `json:"upstream_id"`
	DisplayName  string          `json:"display_name"`
	Available    bool            `json:"available"`
	Capabilities map[string]bool `json:"capabilities"`
	LastSeen     string          `json:"last_seen"`
	Registered   bool            `json:"registered"`
}
type Model struct {
	ID              string          `json:"id"`
	Alias           string          `json:"alias"`
	EngineID        string          `json:"engine_id"`
	UpstreamModelID string          `json:"upstream_model_id"`
	DisplayName     string          `json:"display_name"`
	Published       bool            `json:"published"`
	Available       bool            `json:"available"`
	Capabilities    map[string]bool `json:"capabilities"`
	AllowedIPs      []string        `json:"allowed_ips"`
	AllowedAPIKeys  []string        `json:"allowed_api_keys"`
	CreatedAt       string          `json:"created_at"`
	UpdatedAt       string          `json:"updated_at"`
}
type APIKey struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	SecretCipher []byte   `json:"-"`
	SecretHash   string   `json:"-"`
	Suffix       string   `json:"-"`
	Masked       string   `json:"masked"`
	Tags         []string `json:"tags"`
	Enabled      bool     `json:"enabled"`
	LastUsedAt   string   `json:"last_used_at"`
	CreatedAt    string   `json:"created_at"`
	UpdatedAt    string   `json:"updated_at"`
}
type Admin struct {
	ID           string `json:"id"`
	Username     string `json:"username"`
	PasswordHash string `json:"-"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
}
type Session struct{ TokenHash, AdminID, CSRFToken, ExpiresAt, CreatedAt string }
type Audit struct {
	ID        string `json:"id"`
	Timestamp string `json:"timestamp"`
	ActorID   string `json:"actor_id"`
	ActorName string `json:"actor_name"`
	SourceIP  string `json:"source_ip"`
	Action    string `json:"action"`
	Target    string `json:"target"`
	Result    string `json:"result"`
	Detail    string `json:"detail"`
}
type Usage struct {
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
	TotalTokens  int64 `json:"total_tokens"`
}
type AccessRecord struct {
	Timestamp     string   `json:"timestamp"`
	SourceIP      string   `json:"source_ip"`
	RequestID     string   `json:"request_id"`
	APIKeyID      string   `json:"api_key_id"`
	APIKeyName    string   `json:"api_key_name"`
	APIKeyTags    []string `json:"api_key_tags"`
	ModelID       string   `json:"model_id"`
	ModelAlias    string   `json:"model_alias"`
	EngineID      string   `json:"engine_id"`
	EngineName    string   `json:"engine_name"`
	UpstreamModel string   `json:"upstream_model"`
	Endpoint      string   `json:"endpoint"`
	Method        string   `json:"method"`
	Status        int      `json:"status"`
	Streaming     bool     `json:"streaming"`
	DurationMS    float64  `json:"duration_ms"`
	TTFTMS        float64  `json:"ttft_ms"`
	Usage
	Prompt    any    `json:"prompt,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
}
type Settings struct {
	ListenAddress           string `json:"listen_address"`
	HealthIntervalSeconds   int    `json:"health_interval_seconds"`
	RequestTimeoutSeconds   int    `json:"request_timeout_seconds"`
	LogRotationBytes        int64  `json:"log_rotation_bytes"`
	LogGenerations          int    `json:"log_generations"`
	StatisticsRetentionDays int    `json:"statistics_retention_days"`
	BackupRetentionDays     int    `json:"backup_retention_days"`
	AutoBackupEnabled       bool   `json:"auto_backup_enabled"`
}

func DefaultSettings() Settings {
	return Settings{"0.0.0.0:8080", 30, 600, 100 * 1024 * 1024, 10, 90, 14, true}
}

type Backup struct {
	ID        string `json:"id"`
	Filename  string `json:"filename"`
	Kind      string `json:"kind"`
	Size      int64  `json:"size"`
	CreatedAt string `json:"created_at"`
}
