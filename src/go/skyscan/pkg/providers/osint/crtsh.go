package osint

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"skyscan/pkg/core"
	"skyscan/pkg/net"
	"strings"
	"time"
)

type CrtShProvider struct {
	client *net.Client
	config *core.Config
}

func NewCrtShProvider(client *net.Client) *CrtShProvider {
	return &CrtShProvider{
		client: client,
	}
}

func (p *CrtShProvider) Name() string {
	return "OSINT"
}

func (p *CrtShProvider) Init(config *core.Config) error {
	p.config = config
	return nil
}

type CrtShResult struct {
	NameValue string `json:"name_value"`
}

func (p *CrtShProvider) Generate(ctx context.Context, keyword string, output chan<- string) {
	// Query crt.sh for %.keyword.s3.amazonaws.com and similar
	// This is a bit tricky as crt.sh can be slow.
	// We'll do one query for the keyword and filter.

	url := fmt.Sprintf("https://crt.sh/?q=%s&output=json", keyword)

	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var results []CrtShResult
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return
	}

	seen := make(map[string]bool)
	for _, res := range results {
		// Split multi-value certs
		names := strings.Split(res.NameValue, "\n")
		for _, name := range names {
			name = strings.TrimSpace(name)
			if seen[name] {
				continue
			}
			seen[name] = true

			// Check if it looks like a cloud bucket
			if strings.Contains(name, "s3.amazonaws.com") ||
				strings.Contains(name, "blob.core.windows.net") ||
				strings.Contains(name, "storage.googleapis.com") {

				// Ensure it starts with http/https
				target := fmt.Sprintf("https://%s", name)
				select {
				case <-ctx.Done():
					return
				case output <- target:
				}
			}
		}
	}
}

func (p *CrtShProvider) Check(ctx context.Context, target string) (*core.Result, error) {
	// Just pass through to client check
	status, size, err := p.client.Check(target)
	if err != nil {
		return nil, err
	}

	if status == 404 {
		return nil, nil
	}

	return &core.Result{
		URL:         target,
		Provider:    "OSINT",
		Status:      status,
		Size:        size,
		Permissions: "FOUND_VIA_CERT",
	}, nil
}
