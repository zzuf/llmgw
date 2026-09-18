package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"llmgw/internal/domain"
)

// Adapter is a native protocol forwarding profile, not a protocol emulator.
type Adapter struct{ engineType string }

func New(engineType string) *Adapter { return &Adapter{engineType: canonicalType(engineType)} }
func canonicalType(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "lmstudio", "lm-studio", "lm_studio":
		return "lmstudio"
	case "mlx", "mlx-lm", "mlx_lm", "mlxserve":
		return "mlx-lm"
	case "omlx":
		return "omlx"
	case "auto", "":
		return "auto"
	default:
		return "openai"
	}
}

// NewHTTPClient has no whole-response timeout, allowing long generations. Each
// operation must use a deadline-bearing context. Credentials never follow redirects.
func NewHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	transport.ResponseHeaderTimeout = 0
	transport.MaxIdleConnsPerHost = 16
	return &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// ValidateBaseURL rejects credentials and implicit query/fragment routing.
func ValidateBaseURL(base string) error { _, err := baseURL(base); return err }
func baseURL(base string) (*url.URL, error) {
	u, err := url.Parse(base)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return nil, invalid("Engine base URL must be an HTTP(S) URL without credentials, query, or fragment")
	}
	return u, nil
}
func endpointURL(base, endpoint string) (string, error) {
	u, err := baseURL(base)
	if err != nil {
		return "", err
	}
	path := strings.TrimRight(u.Path, "/")
	if !strings.HasSuffix(path, "/v1") {
		path += "/v1"
	}
	u.Path = path + strings.TrimPrefix(endpoint, "/v1")
	u.RawPath = ""
	return u.String(), nil
}
func (a *Adapter) request(ctx context.Context, client *http.Client, e domain.Engine, secret, method, endpoint string, body []byte) (*http.Response, error) {
	target, err := endpointURL(e.BaseURL, endpoint)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return nil, invalid("Cannot construct upstream request")
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if endpoint == "/v1/messages" {
		req.Header.Set("Anthropic-Version", "2023-06-01")
	}
	switch e.AuthType {
	case "", "none":
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+secret)
	case "x-api-key":
		req.Header.Set("X-Api-Key", secret)
	default:
		return nil, invalid("Unsupported engine authentication type")
	}
	if client == nil {
		client = NewHTTPClient()
	}
	// Copy, so callers' clients are not mutated and their cookie jars never attach
	// gateway/browser credentials to an upstream request.
	isolated := *client
	isolated.Jar = nil
	isolated.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := isolated.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			return nil, context.DeadlineExceeded
		}
		return nil, errors.New("Unable to connect to upstream engine")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		resp.Body.Close()
		code, message := "upstream_error", "Upstream engine rejected the request"
		if method == http.MethodPost && (resp.StatusCode == 404 || resp.StatusCode == 405 || resp.StatusCode == 501) {
			code, message = "unsupported_endpoint", "Upstream engine does not support this native endpoint"
		}
		return nil, &Error{Code: code, Message: message, Status: resp.StatusCode}
	}
	return resp, nil
}

func (a *Adapter) Do(ctx context.Context, client *http.Client, e domain.Engine, secret string, req *Request, upstreamModel string) (*http.Response, error) {
	if req == nil || !validEndpoint(req.Endpoint) {
		return nil, &Error{Code: "unsupported_endpoint", Message: "This native protocol endpoint is not supported", Status: 501}
	}
	body, err := req.Encode(upstreamModel)
	if err != nil {
		return nil, err
	}
	return a.request(ctx, client, e, secret, http.MethodPost, req.Endpoint, body)
}

// ListModels only returns successful, validated discovery snapshots. Callers must
// retain their prior discoveries when this function returns an error.
func (a *Adapter) ListModels(ctx context.Context, client *http.Client, e domain.Engine, secret string) ([]domain.UpstreamModel, string, error) {
	resp, err := a.request(ctx, client, e, secret, http.MethodGet, "/v1/models", nil)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	// Model discovery is finite metadata, unlike inference request/response bodies.
	const maxDiscovery = 32 << 20
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxDiscovery+1))
	if err != nil || len(data) > maxDiscovery {
		return nil, "", upstreamError("Upstream model discovery could not be read")
	}
	object, err := decodeObject(bytes.NewReader(data))
	if err != nil {
		return nil, "", upstreamError("Upstream model discovery is not a valid JSON object")
	}
	raw, ok := object["data"]
	if !ok {
		raw, ok = object["models"]
	}
	var entries []map[string]json.RawMessage
	if !ok || json.Unmarshal(raw, &entries) != nil || entries == nil {
		return nil, "", upstreamError("Upstream model discovery must contain a model array")
	}
	detected := a.engineType
	if detected == "auto" {
		detected = detectType(resp.Header, entries)
	}
	models := make([]domain.UpstreamModel, 0, len(entries))
	seen := map[string]bool{}
	for _, entry := range entries {
		id := stringField(entry, "id")
		if id == "" {
			id = stringField(entry, "key")
		}
		if id == "" {
			id = stringField(entry, "name")
		}
		if strings.TrimSpace(id) == "" {
			return nil, "", upstreamError("Upstream model discovery contains a model without an identifier")
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		display := stringField(entry, "display_name")
		if display == "" {
			display = stringField(entry, "name")
		}
		if display == "" {
			display = id
		}
		models = append(models, domain.UpstreamModel{EngineID: e.ID, UpstreamID: id, DisplayName: display, Available: true, Capabilities: modelCapabilities(detected, entry)})
	}
	return models, detected, nil
}
func stringField(fields map[string]json.RawMessage, key string) string {
	var s string
	_ = json.Unmarshal(fields[key], &s)
	return s
}
func detectType(headers http.Header, entries []map[string]json.RawMessage) string {
	markers := []string{headers.Get("Server"), headers.Get("X-Powered-By")}
	for _, entry := range entries {
		markers = append(markers, stringField(entry, "owned_by"))
	}
	for _, marker := range markers {
		lower := strings.ToLower(marker)
		if strings.Contains(lower, "lmstudio") || strings.Contains(lower, "lm studio") {
			return "lmstudio"
		}
		if strings.Contains(lower, "omlx") {
			return "omlx"
		}
		if strings.Contains(lower, "mlx-lm") || strings.Contains(lower, "mlx_lm") {
			return "mlx-lm"
		}
	}
	return "openai"
}
func modelCapabilities(profile string, entry map[string]json.RawMessage) map[string]bool {
	capabilities := map[string]bool{"chat_completions": false, "responses": false, "completions": false, "embeddings": false, "rerank": false, "messages": false, "streaming": false, "tools": false, "vision": false}
	kind := strings.ToLower(stringField(entry, "type"))
	if kind == "" {
		kind = strings.ToLower(stringField(entry, "model_type"))
	}
	switch kind {
	case "embedding", "embeddings", "text-embedding":
		capabilities["embeddings"] = true
	case "reranker", "rerank", "cross-encoder":
		capabilities["rerank"] = true
	default:
		capabilities["chat_completions"] = true
		capabilities["streaming"] = true
		if profile == "lmstudio" || profile == "mlx-lm" || profile == "omlx" {
			capabilities["completions"] = true
		}
		if profile == "lmstudio" {
			capabilities["responses"] = true
			capabilities["messages"] = true
		}
		if profile == "omlx" {
			capabilities["messages"] = true
		}
		if kind == "vlm" || kind == "vision" {
			capabilities["vision"] = true
		}
	}
	var native map[string]json.RawMessage
	if json.Unmarshal(entry["capabilities"], &native) == nil {
		for key, raw := range native {
			if key == "trained_for_tool_use" || key == "tool_use" || key == "function_calling" {
				key = "tools"
			}
			if key == "stream" {
				key = "streaming"
			}
			if _, ok := capabilities[key]; ok {
				var enabled bool
				if json.Unmarshal(raw, &enabled) == nil {
					capabilities[key] = enabled
				}
			}
		}
	}
	var endpoints []string
	if json.Unmarshal(entry["supported_endpoints"], &endpoints) == nil {
		for _, endpoint := range endpoints {
			key := strings.TrimPrefix(endpoint, "/v1/")
			key = strings.ReplaceAll(key, "/", "_")
			if _, ok := capabilities[key]; ok {
				capabilities[key] = true
			}
		}
	}
	return capabilities
}
