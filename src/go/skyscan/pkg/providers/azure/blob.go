package azure

import (
	"context"
	"fmt"
	"skyscan/pkg/core"
	"skyscan/pkg/net"
)

type BlobProvider struct {
	client *net.Client
	config *core.Config
}

func NewBlobProvider(client *net.Client) *BlobProvider {
	return &BlobProvider{
		client: client,
	}
}

func (p *BlobProvider) Name() string {
	return "Azure"
}

func (p *BlobProvider) Init(config *core.Config) error {
	p.config = config
	return nil
}

func (p *BlobProvider) Generate(ctx context.Context, keyword string, output chan<- string) {
	// Azure Storage Accounts must be lowercase and alphanumeric, 3-24 chars
	// We need to be careful with mutations.

	// Base
	select {
	case <-ctx.Done():
		return
	case output <- fmt.Sprintf("https://%s.blob.core.windows.net", keyword):
	}

	for _, mut := range p.config.Mutations {
		// Suffix
		select {
		case <-ctx.Done():
			return
		case output <- fmt.Sprintf("https://%s%s.blob.core.windows.net", keyword, mut):
		}

		// Prefix
		select {
		case <-ctx.Done():
			return
		case output <- fmt.Sprintf("https://%s%s.blob.core.windows.net", mut, keyword):
		}
	}
}

func (p *BlobProvider) Check(ctx context.Context, target string) (*core.Result, error) {
	// 1. Check Storage Account Existence
	status, _, err := p.client.Check(target)
	if err != nil {
		return nil, err
	}

	// If hostname doesn't resolve or 404 on root, account might not exist
	// Azure returns 400 Bad Request on root usually if account exists but request is malformed (no container)
	// Or 404 if account doesn't exist?
	// Actually, checking root often returns 400 InvalidUri or similar if account exists.
	// If account doesn't exist, DNS fails.

	// If we get here, DNS resolved (mostly).

	// For this MVP, if we get a response, the account exists.
	// Now check for common containers?
	// That would require more requests. For "Zero to Hero" we should do it.

	containers := []string{"backup", "public", "images", "logs", "content"}

	for _, container := range containers {
		containerUrl := fmt.Sprintf("%s/%s", target, container)
		cStatus, cSize, _ := p.client.Check(containerUrl)

		if cStatus == 200 {
			return &core.Result{
				URL:         containerUrl,
				Provider:    "Azure",
				Status:      cStatus,
				Size:        cSize,
				Permissions: "PUBLIC",
			}, nil
		}
	}

	// If no containers found, but account exists, report the account
	return &core.Result{
		URL:         target,
		Provider:    "Azure",
		Status:      status,
		Size:        0,
		Permissions: "ACCOUNT_FOUND",
	}, nil
}
