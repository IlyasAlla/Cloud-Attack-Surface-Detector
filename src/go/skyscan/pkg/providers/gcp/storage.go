package gcp

import (
	"context"
	"fmt"
	"skyscan/pkg/core"
	"skyscan/pkg/net"
)

type StorageProvider struct {
	client *net.Client
	config *core.Config
}

func NewStorageProvider(client *net.Client) *StorageProvider {
	return &StorageProvider{
		client: client,
	}
}

func (p *StorageProvider) Name() string {
	return "GCP"
}

func (p *StorageProvider) Init(config *core.Config) error {
	p.config = config
	return nil
}

func (p *StorageProvider) Generate(ctx context.Context, keyword string, output chan<- string) {
	// Base
	select {
	case <-ctx.Done():
		return
	case output <- fmt.Sprintf("https://storage.googleapis.com/%s", keyword):
	}

	for _, mut := range p.config.Mutations {
		// Suffix
		select {
		case <-ctx.Done():
			return
		case output <- fmt.Sprintf("https://storage.googleapis.com/%s%s", keyword, mut):
		}

		// Prefix
		select {
		case <-ctx.Done():
			return
		case output <- fmt.Sprintf("https://storage.googleapis.com/%s%s", mut, keyword):
		}

		// Separator
		select {
		case <-ctx.Done():
			return
		case output <- fmt.Sprintf("https://storage.googleapis.com/%s-%s", keyword, mut):
		}
	}
}

func (p *StorageProvider) Check(ctx context.Context, target string) (*core.Result, error) {
	status, size, err := p.client.Check(target)
	if err != nil {
		return nil, err
	}

	if status == 404 {
		return nil, nil
	}

	perms := "UNKNOWN"
	if status == 200 {
		perms = "PUBLIC"
	} else if status == 403 {
		perms = "PROTECTED"
	}

	return &core.Result{
		URL:         target,
		Provider:    "GCP",
		Status:      status,
		Size:        size,
		Permissions: perms,
	}, nil
}
