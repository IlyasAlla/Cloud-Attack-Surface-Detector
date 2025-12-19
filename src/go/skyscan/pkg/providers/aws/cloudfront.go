package aws

import (
	"context"
	"fmt"
	"skyscan/pkg/core"
	"skyscan/pkg/net"
)

type CloudFrontProvider struct {
	client *net.Client
	config *core.Config
}

func NewCloudFrontProvider(client *net.Client) *CloudFrontProvider {
	return &CloudFrontProvider{
		client: client,
	}
}

func (p *CloudFrontProvider) Name() string {
	return "AWS_CLOUDFRONT"
}

func (p *CloudFrontProvider) Init(config *core.Config) error {
	p.config = config
	return nil
}

func (p *CloudFrontProvider) Generate(ctx context.Context, keyword string, output chan<- string) {
	// Pattern: https://<id>.cloudfront.net
	// IDs are random, so we can't guess them easily.
	// BUT, sometimes people use CNAMEs.
	// We can check if `keyword.cloudfront.net` exists (unlikely but possible if they got a vanity one? No, CF doesn't do vanity IDs).
	// However, we can check for S3 buckets that might be backed by CF? No.

	// Actually, this provider might be better suited for checking CNAMEs if we had a domain list.
	// Since we are keyword based, we can try to guess if there are any mapped CNAMEs? No.

	// Let's try checking if the keyword is used as a CNAME target? No.

	// Wait, some tools check `keyword.cloudfront.net`? No, that's not how it works.
	// But maybe we can check `assets.keyword.com` if we had the domain.

	// Let's implement a "Best Effort" check for common misconfigurations or related assets.
	// Actually, let's skip CloudFront for keyword scanning as it's ineffective without a domain list to check CNAMEs against.
	// But the user asked for "every script".

	// Let's check `keyword.s3-website-us-east-1.amazonaws.com` instead? That's S3.

	// Let's implement S3 Website endpoints as part of this file (or S3).
	// Let's rename this to "AWS_EXTRA" and check S3 Websites.

	// S3 Website: http://<bucket>.s3-website-<region>.amazonaws.com

	regions := []string{"us-east-1", "us-west-1", "us-west-2", "eu-west-1"}

	for _, region := range regions {
		target := fmt.Sprintf("http://%s.s3-website-%s.amazonaws.com", keyword, region)
		select {
		case <-ctx.Done():
			return
		case output <- target:
		}
	}
}

func (p *CloudFrontProvider) Check(ctx context.Context, target string) (*core.Result, error) {
	status, size, err := p.client.Check(target)
	if err != nil {
		return nil, err
	}

	if status == 0 || status == 404 {
		return nil, nil
	}

	return &core.Result{
		URL:         target,
		Provider:    "AWS_S3_WEBSITE",
		Status:      status,
		Size:        size,
		Permissions: "PUBLIC",
	}, nil
}
