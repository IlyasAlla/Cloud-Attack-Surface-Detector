package core

import (
	"context"
)

// Provider defines the interface for cloud storage providers
type Provider interface {
	Name() string
	// Init loads any necessary resources (e.g. wordlists)
	Init(config *Config) error
	// Generate emits candidate URLs into a channel
	Generate(ctx context.Context, keyword string, output chan<- string)
	// Check validates a specific target. Returns result or error.
	Check(ctx context.Context, target string) (*Result, error)
}
