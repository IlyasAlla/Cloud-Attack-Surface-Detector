package aws

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"skyscan/pkg/core"
	"skyscan/pkg/net"
	"strings"
	"sync"
)

// S3ProviderV2 implements enhanced S3 enumeration with:
// 1. DNS-based stealth discovery (bypasses S3 logging)
// 2. HTTP validation for accessible buckets
// 3. Region detection via x-amz-bucket-region header
// 4. ACL parsing for permission analysis
type S3ProviderV2 struct {
	httpClient  *net.Client
	dnsResolver *net.DNSResolver
	config      *core.Config
	mu          sync.RWMutex
	regionCache map[string]string
}

// S3 regions for regional endpoint enumeration
var s3Regions = []string{
	"us-east-1", "us-east-2", "us-west-1", "us-west-2",
	"eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-central-2",
	"eu-north-1", "eu-south-1", "eu-south-2",
	"ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
	"ap-southeast-1", "ap-southeast-2", "ap-southeast-3", "ap-southeast-4",
	"ap-south-1", "ap-south-2", "ap-east-1",
	"sa-east-1", "ca-central-1", "ca-west-1",
	"me-south-1", "me-central-1",
	"af-south-1", "il-central-1",
}

func NewS3ProviderV2(httpClient *net.Client, dnsResolver *net.DNSResolver) *S3ProviderV2 {
	return &S3ProviderV2{
		httpClient:  httpClient,
		dnsResolver: dnsResolver,
		regionCache: make(map[string]string),
	}
}

func (p *S3ProviderV2) Name() string {
	return "AWS-S3-V2"
}

func (p *S3ProviderV2) Init(config *core.Config) error {
	p.config = config
	return nil
}

// Generate creates candidate bucket URLs with intelligent mutations
func (p *S3ProviderV2) Generate(ctx context.Context, keyword string, output chan<- string) {
	// Standard S3 endpoint formats
	endpoints := []string{
		"%s.s3.amazonaws.com",            // Virtual-hosted style
		"s3.amazonaws.com/%s",            // Path style (legacy)
		"%s.s3-accelerate.amazonaws.com", // Transfer Acceleration
	}

	// Base keyword
	for _, ep := range endpoints {
		select {
		case <-ctx.Done():
			return
		case output <- fmt.Sprintf("http://"+ep, keyword):
		}
	}

	// Apply mutations from config
	for _, mut := range p.config.Mutations {
		for _, ep := range endpoints[:1] { // Only use virtual-hosted for mutations
			// Suffix mutations
			select {
			case <-ctx.Done():
				return
			case output <- fmt.Sprintf("http://"+ep, keyword+mut):
			case output <- fmt.Sprintf("http://"+ep, keyword+"-"+mut):
			case output <- fmt.Sprintf("http://"+ep, keyword+"_"+mut):
			case output <- fmt.Sprintf("http://"+ep, keyword+"."+mut):
			}

			// Prefix mutations
			select {
			case <-ctx.Done():
				return
			case output <- fmt.Sprintf("http://"+ep, mut+keyword):
			case output <- fmt.Sprintf("http://"+ep, mut+"-"+keyword):
			case output <- fmt.Sprintf("http://"+ep, mut+"_"+keyword):
			case output <- fmt.Sprintf("http://"+ep, mut+"."+keyword):
			}
		}
	}

	// Regional endpoints (for buckets in specific regions)
	for _, region := range s3Regions {
		select {
		case <-ctx.Done():
			return
		case output <- fmt.Sprintf("http://%s.s3.%s.amazonaws.com", keyword, region):
		}
	}
}

// Check performs hybrid DNS + HTTP validation
func (p *S3ProviderV2) Check(ctx context.Context, target string) (*core.Result, error) {
	// Extract bucket name from URL
	bucketName := extractBucketName(target)
	if bucketName == "" {
		return nil, fmt.Errorf("could not extract bucket name from %s", target)
	}

	// Phase 1: DNS Check (stealth)
	dnsHost := fmt.Sprintf("%s.s3.amazonaws.com", bucketName)
	dnsResult := p.dnsResolver.CheckExists(ctx, dnsHost)

	if dnsResult.Error != nil {
		return &core.Result{
			URL:      target,
			Provider: "AWS",
			Error:    dnsResult.Error.Error(),
		}, nil
	}

	if !dnsResult.Exists {
		// NXDOMAIN - bucket does not exist
		return nil, nil
	}

	// Phase 2: HTTP Check (detailed analysis)
	status, size, err := p.httpClient.Check(target)
	if err != nil {
		return &core.Result{
			URL:      target,
			Provider: "AWS",
			Status:   0,
			Error:    err.Error(),
		}, nil
	}

	result := &core.Result{
		URL:      target,
		Provider: "AWS",
		Status:   status,
		Size:     size,
	}

	// Analyze permissions based on status code
	switch status {
	case 200:
		result.Permissions = "PUBLIC_READ"
		// Attempt to list files
		if body, err := p.httpClient.GetBody(target); err == nil {
			result.Files = parseS3XMLv2(body)
		}
	case 204:
		result.Permissions = "PUBLIC_EMPTY"
	case 403:
		result.Permissions = "AUTHENTICATED"
		// Could be accessible with valid AWS creds
	case 404:
		// This shouldn't happen if DNS resolved, but bucket might be deleted
		return nil, nil
	case 301, 307:
		result.Permissions = "REDIRECT"
		// Bucket exists but wrong region - detect region
		region := p.detectRegion(target)
		if region != "" {
			result.Error = fmt.Sprintf("redirect to region: %s", region)
		}
	default:
		result.Permissions = "UNKNOWN"
	}

	return result, nil
}

// CheckWithACL performs deep ACL analysis (requires valid bucket)
func (p *S3ProviderV2) CheckWithACL(ctx context.Context, bucketName string) *S3ACLResult {
	result := &S3ACLResult{
		BucketName: bucketName,
	}

	// Check for public listing (/?acl suffix)
	aclURL := fmt.Sprintf("http://%s.s3.amazonaws.com/?acl", bucketName)
	body, err := p.httpClient.GetBody(aclURL)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	// Parse ACL XML
	var acl AccessControlPolicy
	if err := xml.Unmarshal(body, &acl); err == nil {
		for _, grant := range acl.AccessControlList.Grant {
			grantee := grant.Grantee.URI
			if strings.Contains(grantee, "AllUsers") {
				result.PublicRead = true
				if grant.Permission == "WRITE" {
					result.PublicWrite = true
				}
			}
			if strings.Contains(grantee, "AuthenticatedUsers") {
				result.AuthenticatedRead = true
			}
		}
	}

	return result
}

// detectRegion attempts to detect the bucket's region via HEAD request
func (p *S3ProviderV2) detectRegion(target string) string {
	// S3 returns x-amz-bucket-region header on 301/307 redirects
	bucketName := extractBucketName(target)
	if bucketName == "" {
		return ""
	}

	// Check cache first
	p.mu.RLock()
	if region, ok := p.regionCache[bucketName]; ok {
		p.mu.RUnlock()
		return region
	}
	p.mu.RUnlock()

	// Make HEAD request to global endpoint
	url := fmt.Sprintf("http://%s.s3.amazonaws.com", bucketName)
	resp, err := http.Head(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	region := resp.Header.Get("x-amz-bucket-region")
	if region != "" {
		p.mu.Lock()
		p.regionCache[bucketName] = region
		p.mu.Unlock()
	}

	return region
}

// Helper to extract bucket name from S3 URL
func extractBucketName(url string) string {
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "https://")

	// Virtual-hosted style: {bucket}.s3.{region}.amazonaws.com
	if strings.Contains(url, ".s3.") && strings.Contains(url, ".amazonaws.com") {
		parts := strings.Split(url, ".s3.")
		if len(parts) > 0 {
			return parts[0]
		}
	}

	// Path style: s3.amazonaws.com/{bucket}
	if strings.HasPrefix(url, "s3.amazonaws.com/") {
		parts := strings.Split(strings.TrimPrefix(url, "s3.amazonaws.com/"), "/")
		if len(parts) > 0 {
			return parts[0]
		}
	}

	return ""
}

// S3ACLResult holds detailed ACL analysis
type S3ACLResult struct {
	BucketName        string
	PublicRead        bool
	PublicWrite       bool
	AuthenticatedRead bool
	Error             string
}

// XML structures for S3 responses
type AccessControlPolicy struct {
	Owner             Owner             `xml:"Owner"`
	AccessControlList AccessControlList `xml:"AccessControlList"`
}

type Owner struct {
	ID          string `xml:"ID"`
	DisplayName string `xml:"DisplayName"`
}

type AccessControlList struct {
	Grant []Grant `xml:"Grant"`
}

type Grant struct {
	Grantee    Grantee `xml:"Grantee"`
	Permission string  `xml:"Permission"`
}

type Grantee struct {
	Type        string `xml:"type,attr"`
	URI         string `xml:"URI"`
	ID          string `xml:"ID"`
	DisplayName string `xml:"DisplayName"`
}

// Minimal XML parser for S3 ListBucketResult
type ListBucketResultV2 struct {
	Contents []struct {
		Key          string `xml:"Key"`
		LastModified string `xml:"LastModified"`
		Size         int64  `xml:"Size"`
		StorageClass string `xml:"StorageClass"`
	} `xml:"Contents"`
	IsTruncated bool   `xml:"IsTruncated"`
	NextMarker  string `xml:"NextContinuationToken"`
}

func parseS3XMLv2(body []byte) []string {
	var result ListBucketResultV2
	if err := xml.Unmarshal(body, &result); err != nil {
		return nil
	}

	var files []string
	for i, item := range result.Contents {
		if i >= 10 { // Limit to first 10 files
			break
		}
		files = append(files, fmt.Sprintf("%s (%d bytes)", item.Key, item.Size))
	}
	return files
}
