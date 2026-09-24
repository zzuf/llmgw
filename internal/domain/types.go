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
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	SecretCipher       []byte   `json:"-"`
	SecretHash         string   `json:"-"`
	Suffix             string   `json:"-"`
	Masked             string   `json:"masked"`
	Tags               []string `json:"tags"`
	Enabled            bool     `json:"enabled"`
	LastUsedAt         string   `json:"last_used_at"`
	CreatedAt          string   `json:"created_at"`
	UpdatedAt          string   `json:"updated_at"`
	InputSafeguardID   *string  `json:"input_safeguard_id"`
	OutputSafeguardID  *string  `json:"output_safeguard_id"`
	BlockControversial bool     `json:"block_controversial"`
}

type Safeguard struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	EngineID        string `json:"engine_id"`
	UpstreamModelID string `json:"upstream_model_id"`
	Adapter         string `json:"adapter"`
	Enabled         bool   `json:"enabled"`
	Available       bool   `json:"available"`
	LastCheck       string `json:"last_check"`
	LastError       string `json:"last_error"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}

// SafeguardBinding is a per-request snapshot; no database transaction spans inference.
type SafeguardBinding struct {
	Safeguard Safeguard
	Engine    Engine
}

type GuardCheck struct {
	Stage         string   `json:"stage"`
	SafeguardID   string   `json:"safeguard_id"`
	SafeguardName string   `json:"safeguard_name"`
	EngineID      string   `json:"engine_id"`
	EngineName    string   `json:"engine_name"`
	UpstreamModel string   `json:"upstream_model"`
	Result        string   `json:"result"`
	Label         string   `json:"label,omitempty"`
	Categories    []string `json:"categories,omitempty"`
	Refusal       string   `json:"refusal,omitempty"`
	DurationMS    float64  `json:"duration_ms"`
	Usage         Usage    `json:"usage"`
	ErrorCode     string   `json:"error_code,omitempty"`
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
	Prompt         any          `json:"prompt,omitempty"`
	ErrorCode      string       `json:"error_code,omitempty"`
	GuardChecks    []GuardCheck `json:"guard_checks,omitempty"`
	UpstreamTTFTMS float64      `json:"upstream_ttft_ms,omitempty"`
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
	GuardTimeoutSeconds     int    `json:"guard_timeout_seconds"`
	GuardMaxTextBytes       int64  `json:"guard_max_text_bytes"`
	GuardMaxSpoolBytes      int64  `json:"guard_max_spool_bytes"`
}

func DefaultSettings() Settings {
	return Settings{ListenAddress: "0.0.0.0:8080", HealthIntervalSeconds: 30, RequestTimeoutSeconds: 600, LogRotationBytes: 100 * 1024 * 1024, LogGenerations: 10, StatisticsRetentionDays: 90, BackupRetentionDays: 14, AutoBackupEnabled: true, GuardTimeoutSeconds: 60, GuardMaxTextBytes: 256 * 1024, GuardMaxSpoolBytes: 64 * 1024 * 1024}
}

type Backup struct {
	ID        string `json:"id"`
	Filename  string `json:"filename"`
	Kind      string `json:"kind"`
	Size      int64  `json:"size"`
	CreatedAt string `json:"created_at"`
}
