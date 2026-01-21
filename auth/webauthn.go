package auth

import (
	"github.com/go-webauthn/webauthn/webauthn"
)

// Config holds WebAuthn configuration
type Config struct {
	RPDisplayName string
	RPID          string
	RPOrigins     []string
}

// NewWebAuthn creates a new WebAuthn instance
func NewWebAuthn(cfg Config) (*webauthn.WebAuthn, error) {
	wconfig := &webauthn.Config{
		RPDisplayName: cfg.RPDisplayName,
		RPID:          cfg.RPID,
		RPOrigins:     cfg.RPOrigins,
	}

	return webauthn.New(wconfig)
}
