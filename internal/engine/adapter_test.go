package engine

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"llmgw/internal/domain"
)

func TestAdapterNativeRoutesAndAuth(t *testing.T) {
	for _, auth := range []string{"none", "bearer", "x-api-key"} {
		t.Run(auth, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/prefix/v1/responses" {
					t.Errorf("path %s", r.URL.Path)
				}
				if r.Header.Get("Cookie") != "" {
					t.Error("unexpected cookie")
				}
				if auth == "bearer" && r.Header.Get("Authorization") != "Bearer engine-secret" {
					t.Error("wrong bearer")
				}
				if auth != "bearer" && r.Header.Get("Authorization") != "" {
					t.Error("unexpected bearer")
				}
				if auth == "x-api-key" && r.Header.Get("X-Api-Key") != "engine-secret" {
					t.Error("wrong api key")
				}
				var body map[string]json.RawMessage
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				if string(body["model"]) != `"native"` || body["input"] == nil || body["messages"] != nil || body["reasoning"] == nil {
					t.Errorf("request %v", body)
				}
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, `{"model":"native","output":[]}`)
			}))
			defer upstream.Close()
			req, err := Parse("/v1/responses", strings.NewReader(`{"model":"alias","input":"hi","reasoning":{"effort":"high"}}`))
			if err != nil {
				t.Fatal(err)
			}
			client := upstream.Client()
			client.Jar, _ = cookiejar.New(nil)
			origin, _ := url.Parse(upstream.URL)
			client.Jar.SetCookies(origin, []*http.Cookie{{Name: "gateway-session", Value: "private", Path: "/"}})
			resp, err := New("lmstudio").Do(context.Background(), client, domain.Engine{BaseURL: upstream.URL + "/prefix/v1/", AuthType: auth}, "engine-secret", req, "native")
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
		})
	}
}

func TestAdapterRejectsRedirectsAndUnsafeBaseURLs(t *testing.T) {
	var hits atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer destination.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	req, _ := Parse("/v1/embeddings", strings.NewReader(`{"model":"m","input":"hello"}`))
	for _, base := range []string{redirect.URL + "/v1", "http://user:password@localhost/v1", "http://localhost/v1?token=secret", "http://localhost/v1#fragment", "file:///v1"} {
		_, err := New("openai").Do(context.Background(), http.DefaultClient, domain.Engine{BaseURL: base, AuthType: "bearer"}, "secret", req, "native")
		if err == nil {
			t.Fatalf("accepted %s", base)
		}
		if strings.Contains(err.Error(), "password") || strings.Contains(err.Error(), "token=secret") {
			t.Fatalf("leaked URL %v", err)
		}
	}
	if hits.Load() != 0 {
		t.Fatal("redirect followed")
	}
}

func TestModelDiscoveryMetadataAndHTTPFailureClassification(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			t.Errorf("path %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Error("auth missing")
		}
		io.WriteString(w, `{"models":[{"key":"llm","display_name":"Vision LLM","type":"llm","capabilities":{"vision":true,"trained_for_tool_use":true}},{"id":"embed","type":"embedding"}]}`)
	}))
	models, detected, err := New("lmstudio").ListModels(context.Background(), upstream.Client(), domain.Engine{ID: "e", BaseURL: upstream.URL + "/v1", AuthType: "bearer"}, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if len(models) != 2 || detected != "lmstudio" || models[0].DisplayName != "Vision LLM" || !models[0].Capabilities["vision"] || !models[0].Capabilities["tools"] || !models[0].Capabilities["responses"] || models[1].Capabilities["chat_completions"] || !models[1].Capabilities["embeddings"] {
		t.Fatalf("discovery %s %+v", detected, models)
	}
	upstream.Close()
	_, _, err = New("auto").ListModels(context.Background(), http.DefaultClient, domain.Engine{BaseURL: upstream.URL + "/v1"}, "")
	var api *Error
	if err == nil || errors.As(err, &api) {
		t.Fatalf("transport classified as HTTP: %v", err)
	}
	failure := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "upstream-secret", 401) }))
	defer failure.Close()
	_, _, err = New("auto").ListModels(context.Background(), failure.Client(), domain.Engine{BaseURL: failure.URL}, "")
	if !errors.As(err, &api) || api.Status != 401 || strings.Contains(err.Error(), "upstream-secret") {
		t.Fatalf("HTTP error %v", err)
	}
}

func TestModelDiscoveryRejectsMalformedSuccess(t *testing.T) {
	for _, body := range []string{`{"error":{"message":"secret"}}`, `{"data":[{}]}`, `{"data":null}`, `{"data":[]} {}`, `<html>bad</html>`} {
		t.Run(body, func(t *testing.T) {
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) }))
			defer up.Close()
			_, _, err := New("auto").ListModels(context.Background(), up.Client(), domain.Engine{BaseURL: up.URL}, "")
			var api *Error
			if !errors.As(err, &api) || api.Status == 0 {
				t.Fatalf("invalid listing accepted/classified transport: %v", err)
			}
		})
	}
}

func TestNativeEmbeddingsAndMessagesKeepTheirProtocols(t *testing.T) {
	for _, tc := range []struct{ endpoint, body string }{
		{"/v1/embeddings", `{"model":"alias","input":["a","b"],"dimensions":256,"encoding_format":"float"}`},
		{"/v1/messages", `{"model":"alias","messages":[{"role":"user","content":"hi"}],"max_tokens":50,"system":"brief"}`},
	} {
		t.Run(tc.endpoint, func(t *testing.T) {
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tc.endpoint {
					t.Errorf("wrong native route %s", r.URL.Path)
				}
				if tc.endpoint == "/v1/messages" && r.Header.Get("Anthropic-Version") == "" {
					t.Error("missing native protocol version")
				}
				data, _ := io.ReadAll(r.Body)
				var got, want map[string]json.RawMessage
				_ = json.Unmarshal(data, &got)
				_ = json.Unmarshal([]byte(tc.body), &want)
				for key, value := range want {
					if key != "model" && string(got[key]) != string(value) {
						t.Errorf("lost native field %s", key)
					}
				}
				io.WriteString(w, `{"model":"native"}`)
			}))
			defer up.Close()
			req, err := Parse(tc.endpoint, strings.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			resp, err := New("openai").Do(context.Background(), NewHTTPClient(), domain.Engine{BaseURL: up.URL}, "", req, "native")
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
		})
	}
}

func TestDiscoveryAutoDetectionAndExplicitCapabilities(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"data":[{"id":"model","owned_by":"omlx","capabilities":{"tools":true,"streaming":false,"responses":true}},{"id":"ranker","owned_by":"omlx","model_type":"reranker"}]}`)
	}))
	defer up.Close()
	models, detected, err := New("auto").ListModels(context.Background(), NewHTTPClient(), domain.Engine{BaseURL: up.URL}, "")
	if err != nil {
		t.Fatal(err)
	}
	if detected != "omlx" || len(models) != 2 || !models[0].Capabilities["responses"] || !models[0].Capabilities["tools"] || models[0].Capabilities["streaming"] || !models[1].Capabilities["rerank"] || models[1].Capabilities["chat_completions"] {
		t.Fatalf("wrong metadata %s %+v", detected, models)
	}
}

func TestMLXServeAdminProfileUsesMLXDefaults(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"data":[{"id":"mlx-community/local-model"}]}`)
	}))
	defer up.Close()
	models, detected, err := New("mlxserve").ListModels(context.Background(), up.Client(), domain.Engine{BaseURL: up.URL}, "")
	if err != nil {
		t.Fatal(err)
	}
	if detected != "mlx-lm" || len(models) != 1 || !models[0].Capabilities["completions"] || models[0].Capabilities["responses"] {
		t.Fatalf("incorrect MLX profile defaults: %s %+v", detected, models)
	}
}
