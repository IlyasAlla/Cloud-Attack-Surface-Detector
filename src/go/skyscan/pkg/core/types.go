package core

// Config holds the configuration for the scan
type Config struct {
	Mutations []string
	Resolvers []string
	Threads   int
	Timeout   int
}

// Result represents a finding
type Result struct {
	URL         string   `json:"url"`
	Provider    string   `json:"provider"`
	Status      int      `json:"status"`
	Size        int64    `json:"size"`
	Permissions string   `json:"permissions"` // e.g., "READ", "WRITE", "PUBLIC"
	Files       []string `json:"files,omitempty"`
	Error       string   `json:"error,omitempty"`
}
