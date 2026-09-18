package gateway

import (
	"net/http"
	"strings"
	"testing"
)

func assertPublicCORS(t *testing.T, header http.Header) {
	t.Helper()
	if header.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("cross-origin API response is not readable: %v", header)
	}
	if header.Get("Access-Control-Allow-Credentials") != "" {
		t.Fatal("public CORS must not enable cookie credentials")
	}
	assertHeaderToken(t, header, "Access-Control-Expose-Headers", "X-Request-ID")
}

func assertHeaderToken(t *testing.T, header http.Header, name, token string) {
	t.Helper()
	for _, value := range header.Values(name) {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return
			}
		}
	}
	t.Fatalf("%s does not include %q: %v", name, token, header.Values(name))
}

func TestPublicCORSPreflightAllowsAllOriginsAndRequestedHeaders(t *testing.T) {
	f := newGatewayFixture(t)
	cases := []struct{ path, method, origin, headers string }{
		{"/v1/models", "GET", "https://client.example", "authorization"},
		{"/v1/chat/completions", "POST", "http://localhost:3000", "authorization, content-type, x-stainless-lang"},
		{"/v1/responses", "POST", "https://another.example:8443", "content-type, x-custom-client"},
		{"/v1/completions", "POST", "null", "authorization, content-type"},
		{"/v1/embeddings", "POST", "http://192.168.1.20:3000", "content-type"},
		{"/v1/rerank", "POST", "https://client.example", "content-type"},
		{"/v1/messages", "POST", "https://client.example", "authorization, content-type, anthropic-version"},
		{"/v1", "GET", "https://client.example", ""},
		{"/v1/", "GET", "https://client.example", ""},
	}
	for _, test := range cases {
		t.Run(test.path, func(t *testing.T) {
			r := requestJSON(t, "OPTIONS", test.path, nil)
			r.RemoteAddr = "203.0.113.10:1234"
			r.Header.Set("Origin", test.origin)
			r.Header.Set("Access-Control-Request-Method", test.method)
			r.Header.Set("Access-Control-Request-Headers", test.headers)
			w := serve(t, f.server, r, http.StatusNoContent)
			assertPublicCORS(t, w.Result().Header)
			assertHeaderToken(t, w.Header(), "Access-Control-Allow-Methods", test.method)
			if test.headers != "" {
				for _, header := range strings.Split(test.headers, ",") {
					assertHeaderToken(t, w.Header(), "Access-Control-Allow-Headers", strings.TrimSpace(header))
				}
			}
			assertHeaderToken(t, w.Header(), "Vary", "Access-Control-Request-Headers")
			if w.Body.Len() != 0 {
				t.Fatalf("preflight returned a body: %s", w.Body.String())
			}
		})
	}
	records := f.accessRecords(t)
	if len(records) != len(cases) {
		t.Fatalf("preflight access logs=%d want=%d", len(records), len(cases))
	}
	for _, record := range records {
		if record.Method != "OPTIONS" || record.Status != http.StatusNoContent || record.EngineID != "" || record.APIKeyID != "" {
			t.Fatalf("incorrect preflight access log: %+v", record)
		}
	}
}

func TestPublicCORSPreflightDoesNotRequireDatabaseOrAuthentication(t *testing.T) {
	r := requestJSON(t, "OPTIONS", "/v1/chat/completions", nil)
	r.Header.Set("Origin", "https://client.example")
	r.Header.Set("Access-Control-Request-Method", "POST")
	r.Header.Set("Access-Control-Request-Headers", "authorization, content-type")
	// No store or upstream exists: preflight must not attempt credential lookup or inference.
	w := serve(t, &Server{}, r, http.StatusNoContent)
	assertPublicCORS(t, w.Result().Header)
}

func TestPublicCORSErrorResponsesRemainReadable(t *testing.T) {
	f := newGatewayFixture(t)
	cases := []struct {
		method, path string
		body         any
		status       int
	}{
		{"POST", "/v1/chat/completions", chatBody("missing"), 404},
		{"POST", "/v1/chat/completions", nil, 400},
		{"DELETE", "/v1/models", nil, 405},
		{"POST", "/v1/unknown", nil, 501},
	}
	for _, test := range cases {
		t.Run(test.method+test.path, func(t *testing.T) {
			r := requestJSON(t, test.method, test.path, test.body)
			r.Header.Set("Origin", "https://client.example")
			w := serve(t, f.server, r, test.status)
			assertPublicCORS(t, w.Result().Header)
		})
	}
}

func TestPublicCORSDoesNotExposeAdminOrOtherRoutes(t *testing.T) {
	f := newGatewayFixture(t)
	cases := []struct {
		method, path string
		status       int
	}{
		{"GET", "/admin/api/session", 403},
		{"GET", "/admin/api/csrf", 403},
		{"POST", "/admin/api/login", 403},
		{"POST", "/admin/api/setup", 403},
		{"OPTIONS", "/admin/api/settings", 403},
		{"GET", "/admin/", 200},
		{"GET", "/setup", 200},
		{"GET", "/health", 200},
		{"OPTIONS", "/v10/models", 404},
	}
	for _, test := range cases {
		t.Run(test.method+test.path, func(t *testing.T) {
			r := requestJSON(t, test.method, test.path, nil)
			r.Header.Set("Origin", "https://client.example")
			r.Header.Set("Sec-Fetch-Site", "cross-site")
			r.Header.Set("Access-Control-Request-Method", "POST")
			w := serve(t, f.server, r, test.status)
			for name := range w.Result().Header {
				if strings.HasPrefix(name, "Access-Control-") {
					t.Fatalf("CORS leaked outside the public API: %s", name)
				}
			}
		})
	}
}
