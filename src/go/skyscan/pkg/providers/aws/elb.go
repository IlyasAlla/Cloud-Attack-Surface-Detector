package aws

import (
	"context"
	"fmt"
	"skyscan/pkg/core"
	"skyscan/pkg/net"
)

type ELBProvider struct {
	client  *net.Client
	config  *core.Config
	regions []string
}

func NewELBProvider(client *net.Client) *ELBProvider {
	return &ELBProvider{
		client: client,
		regions: []string{
			"us-east-1", "us-east-2", "us-west-1", "us-west-2",
			"eu-west-1", "eu-central-1",
		},
	}
}

func (p *ELBProvider) Name() string {
	return "AWS_ELB"
}

func (p *ELBProvider) Init(config *core.Config) error {
	p.config = config
	return nil
}

func (p *ELBProvider) Generate(ctx context.Context, keyword string, output chan<- string) {
	// Pattern: http://<name>.<region>.elb.amazonaws.com
	// Note: Modern ALBs have random IDs, but Classic ELBs use names.
	// Also NLBs.

	for _, region := range p.regions {
		// Base
		target := fmt.Sprintf("http://%s.%s.elb.amazonaws.com", keyword, region)
		select {
		case <-ctx.Done():
			return
		case output <- target:
		}

		// Mutations
		for _, mut := range p.config.Mutations {
			target := fmt.Sprintf("http://%s-%s.%s.elb.amazonaws.com", keyword, mut, region)
			select {
			case <-ctx.Done():
				return
			case output <- target:
			}
		}
	}
}

func (p *ELBProvider) Check(ctx context.Context, target string) (*core.Result, error) {
	status, size, err := p.client.Check(target)
	if err != nil {
		return nil, err
	}

	if status == 0 {
		return nil, nil
	}

	return &core.Result{
		URL:         target,
		Provider:    "AWS_ELB",
		Status:      status,
		Size:        size,
		Permissions: "FOUND",
	}, nil
}
