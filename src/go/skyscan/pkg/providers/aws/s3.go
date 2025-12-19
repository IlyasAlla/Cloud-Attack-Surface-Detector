package aws

import (
	"context"
	"encoding/xml"
	"fmt"
	"skyscan/pkg/core"
	"skyscan/pkg/net"
)

type S3Provider struct {
	client *net.Client
	config *core.Config
}

func NewS3Provider(client *net.Client) *S3Provider {
	return &S3Provider{
		client: client,
	}
}

func (p *S3Provider) Name() string {
	return "AWS"
}

func (p *S3Provider) Init(config *core.Config) error {
	p.config = config
	return nil
}

func (p *S3Provider) Generate(ctx context.Context, keyword string, output chan<- string) {
	// Base bucket
	select {
	case <-ctx.Done():
		return
	case output <- fmt.Sprintf("http://%s.s3.amazonaws.com", keyword):
	}

	// Mutations
	for _, mut := range p.config.Mutations {
		// Suffix
		select {
		case <-ctx.Done():
			return
		case output <- fmt.Sprintf("http://%s%s.s3.amazonaws.com", keyword, mut):
		}

		// Prefix
		select {
		case <-ctx.Done():
			return
		case output <- fmt.Sprintf("http://%s%s.s3.amazonaws.com", mut, keyword):
		}

		// Separator mutations (keyword-mut, keyword.mut, etc.)
		select {
		case <-ctx.Done():
			return
		case output <- fmt.Sprintf("http://%s-%s.s3.amazonaws.com", keyword, mut):
		}
	}
}

func (p *S3Provider) Check(ctx context.Context, target string) (*core.Result, error) {
	status, size, err := p.client.Check(target)
	if err != nil {
		return nil, err
	}

	// Filter for interesting codes
	if status == 404 {
		return nil, nil // Not found
	}

	perms := "UNKNOWN"
	var files []string

	if status == 200 {
		perms = "PUBLIC"

		// Attempt to list files (parse XML)
		body, err := p.client.GetBody(target)
		if err == nil {
			files = parseS3XML(body)
		}
	} else if status == 403 {
		perms = "PROTECTED"
	}

	return &core.Result{
		URL:         target,
		Provider:    "AWS",
		Status:      status,
		Size:        size,
		Permissions: perms,
		Files:       files,
	}, nil
}

// Minimal XML parser for S3 ListBucketResult
type ListBucketResult struct {
	Contents []struct {
		Key string `xml:"Key"`
	} `xml:"Contents"`
}

func parseS3XML(body []byte) []string {
	var result ListBucketResult
	if err := xml.Unmarshal(body, &result); err != nil {
		return nil
	}

	var files []string
	for i, item := range result.Contents {
		if i >= 5 {
			break
		}
		files = append(files, item.Key)
	}
	return files
}
