package config

import (
	"llmgw/internal/domain"
	"testing"
)

func TestGuardSettingsBounds(t *testing.T) {
	if err := Validate(domain.DefaultSettings()); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*domain.Settings)
	}{
		{"zero timeout", func(s *domain.Settings) { s.GuardTimeoutSeconds = 0 }},
		{"excessive timeout", func(s *domain.Settings) { s.GuardTimeoutSeconds = 86401 }},
		{"zero text limit", func(s *domain.Settings) { s.GuardMaxTextBytes = 0 }},
		{"excessive text limit", func(s *domain.Settings) { s.GuardMaxTextBytes = 16<<20 + 1 }},
		{"zero spool limit", func(s *domain.Settings) { s.GuardMaxSpoolBytes = 0 }},
		{"excessive spool limit", func(s *domain.Settings) { s.GuardMaxSpoolBytes = 1<<30 + 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := domain.DefaultSettings()
			tc.mutate(&s)
			if err := Validate(s); err == nil {
				t.Fatal("invalid guard bounds accepted")
			}
		})
	}
	max := domain.DefaultSettings()
	max.GuardTimeoutSeconds = 86400
	max.GuardMaxTextBytes = 16 << 20
	max.GuardMaxSpoolBytes = 1 << 30
	if err := Validate(max); err != nil {
		t.Fatal(err)
	}
}
