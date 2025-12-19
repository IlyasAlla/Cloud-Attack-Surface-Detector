package aws

import (
	"context"
	"fmt"
	"skyscan/pkg/core"
	"skyscan/pkg/net"
)

type ElasticBeanstalkProvider struct {
	client  *net.Client
	config  *core.Config
	regions []string
}

func NewElasticBeanstalkProvider(client *net.Client) *ElasticBeanstalkProvider {
	return &ElasticBeanstalkProvider{
		client: client,
		regions: []string{
			"us-east-1", "us-east-2", "us-west-1", "us-west-2",
			"eu-west-1", "eu-central-1", "eu-west-2",
			"ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
		},
	}
}

func (p *ElasticBeanstalkProvider) Name() string {
	return "AWS_BEANSTALK"
}

func (p *ElasticBeanstalkProvider) Init(config *core.Config) error {
	p.config = config
	return nil
}

func (p *ElasticBeanstalkProvider) Generate(ctx context.Context, keyword string, output chan<- string) {
	// Pattern: http://<appname>.<region>.elasticbeanstalk.com

	for _, region := range p.regions {
		// Base
		target := fmt.Sprintf("http://%s.%s.elasticbeanstalk.com", keyword, region)
		select {
		case <-ctx.Done():
			return
		case output <- target:
		}

		// Mutations
		for _, mut := range p.config.Mutations {
			// Suffix
			target := fmt.Sprintf("http://%s%s.%s.elasticbeanstalk.com", keyword, mut, region)
			select {
			case <-ctx.Done():
				return
			case output <- target:
			}

			// Separator
			target = fmt.Sprintf("http://%s-%s.%s.elasticbeanstalk.com", keyword, mut, region)
			select {
			case <-ctx.Done():
				return
			case output <- target:
			}
		}
	}
}

func (p *ElasticBeanstalkProvider) Check(ctx context.Context, target string) (*core.Result, error) {
	status, size, err := p.client.Check(target)
	if err != nil {
		return nil, err
	}

	// Beanstalk returns 404 (NXDOMAIN) if not found usually.
	// If DNS resolves, it might be a CNAME to something else or the app itself.
	// If HTTP returns 200/302/401/403, it exists.

	if status == 0 { // DNS failure or connection refused
		return nil, nil
	}

	return &core.Result{
		URL:         target,
		Provider:    "AWS_BEANSTALK",
		Status:      status,
		Size:        size,
		Permissions: "FOUND",
	}, nil
}
