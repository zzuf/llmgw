// Package safeguard performs fail-closed, protocol-aware text moderation.
package safeguard

import "llmgw/internal/domain"

// Error contains only controlled text suitable for the public error envelope.
type Error struct {
	Code    string
	Message string
	Status  int
}

func (e *Error) Error() string { return e.Message }

type Verdict struct {
	Label      string
	Categories []string
	Refusal    string
	Usage      domain.Usage
}

func unavailable() error {
	return &Error{Code: "guard_unavailable", Message: "Safeguard could not produce a complete valid verdict", Status: 503}
}

func unsupported() error {
	return &Error{Code: "unsupported_guard_content", Message: "Safeguard supports only complete, interpretable text content", Status: 400}
}

func limitExceeded() error {
	return &Error{Code: "guard_limit_exceeded", Message: "Safeguard inspection or buffering limit exceeded", Status: 503}
}
