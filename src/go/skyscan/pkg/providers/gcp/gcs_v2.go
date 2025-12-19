package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"skyscan/pkg/core"
	"skyscan/pkg/net"
	"strings"
)

// GCSProviderV2 implements Google Cloud Storage enumeration with:
// 1. Unauthenticated bucket discovery
// 2. JSON API for bucket metadata
// 3. Public access detection
type GCSProviderV2 struct {
	httpClient  *net.Client
	dnsResolver *net.DNSResolver
	config      *core.Config
}

// GCS regions for regional bucket enumeration
var gcsRegions = []string{
	// Multi-regional
	"us", "eu", "asia",
	// Regional (US)
	"us-central1", "us-east1", "us-east4", "us-east5",
	"us-west1", "us-west2", "us-west3", "us-west4", "us-south1",
	// Regional (Europe)
	"europe-west1", "europe-west2", "europe-west3", "europe-west4",
	"europe-west6", "europe-west8", "europe-west9", "europe-west10",
	"europe-west12", "europe-north1", "europe-central2", "europe-southwest1",
	// Regional (Asia)
	"asia-east1", "asia-east2", "asia-northeast1", "asia-northeast2", "asia-northeast3",
	"asia-south1", "asia-south2", "asia-southeast1", "asia-southeast2",
	// Regional (Other)
	"australia-southeast1", "australia-southeast2",
	"southamerica-east1", "southamerica-west1",
	"northamerica-northeast1", "northamerica-northeast2",
	"me-central1", "me-central2", "me-west1",
	"africa-south1",
}

func NewGCSProviderV2(httpClient *net.Client, dnsResolver *net.DNSResolver) *GCSProviderV2 {
	return &GCSProviderV2{
		httpClient:  httpClient,
		dnsResolver: dnsResolver,
	}
}

func (p *GCSProviderV2) Name() string {
	return "GCP-GCS-V2"
}

func (p *GCSProviderV2) Init(config *core.Config) error {
	p.config = config
	return nil
}

// Generate creates candidate GCS bucket URLs
func (p *GCSProviderV2) Generate(ctx context.Context, keyword string, output chan<- string) {
	// GCS endpoint formats
	endpoints := []string{
		"storage.googleapis.com/%s", // Path style (JSON API)
		"%s.storage.googleapis.com", // Virtual-hosted style
	}

	// Base keyword
	for _, ep := range endpoints {
		select {
		case <-ctx.Done():
			return
		case output <- fmt.Sprintf("http://"+ep, keyword):
		}
	}

	// Apply mutations
	for _, mut := range p.config.Mutations {
		for _, ep := range endpoints[:1] { // Use path style for mutations
			// Suffix
			select {
			case <-ctx.Done():
				return
			case output <- fmt.Sprintf("http://"+ep, keyword+"-"+mut):
			case output <- fmt.Sprintf("http://"+ep, keyword+"_"+mut):
			case output <- fmt.Sprintf("http://"+ep, keyword+"."+mut):
			}

			// Prefix
			select {
			case <-ctx.Done():
				return
			case output <- fmt.Sprintf("http://"+ep, mut+"-"+keyword):
			case output <- fmt.Sprintf("http://"+ep, mut+"_"+keyword):
			}
		}
	}

	// Common GCP project naming patterns
	gcpPatterns := []string{
		"%s-bucket",
		"%s-storage",
		"%s-assets",
		"%s-backup",
		"%s-data",
		"gcp-%s",
		"google-%s",
	}

	for _, pattern := range gcpPatterns {
		select {
		case <-ctx.Done():
			return
		case output <- fmt.Sprintf("http://storage.googleapis.com/"+pattern, keyword):
		}
	}
}

// Check validates a GCS bucket URL
func (p *GCSProviderV2) Check(ctx context.Context, target string) (*core.Result, error) {
	bucketName := extractGCSBucket(target)
	if bucketName == "" {
		return nil, fmt.Errorf("could not extract bucket from %s", target)
	}

	// Phase 1: DNS Check
	dnsHost := fmt.Sprintf("%s.storage.googleapis.com", bucketName)
	dnsResult := p.dnsResolver.CheckExists(ctx, dnsHost)

	// GCS might not have DNS entry for path-style URLs, so also try HTTP
	if !dnsResult.Exists && dnsResult.Error == nil {
		// Try the main storage endpoint
		dnsResult = p.dnsResolver.CheckExists(ctx, "storage.googleapis.com")
	}

	// Phase 2: HTTP Check
	// Use JSON API for better response parsing
	checkURL := fmt.Sprintf("https://storage.googleapis.com/storage/v1/b/%s?projection=noAcl", bucketName)

	status, _, err := p.httpClient.Check(checkURL)
	if err != nil {
		// Fallback to simple check
		checkURL = target
		status, _, err = p.httpClient.Check(checkURL)
		if err != nil {
			return &core.Result{
				URL:      target,
				Provider: "GCP",
				Error:    err.Error(),
			}, nil
		}
	}

	result := &core.Result{
		URL:      target,
		Provider: "GCP",
		Status:   status,
	}

	switch status {
	case 200:
		result.Permissions = "PUBLIC_METADATA"
		// Try to list objects
		listURL := fmt.Sprintf("https://storage.googleapis.com/storage/v1/b/%s/o", bucketName)
		if body, err := p.httpClient.GetBody(listURL); err == nil {
			result.Files = parseGCSJSON(body)
			if len(result.Files) > 0 {
				result.Permissions = "PUBLIC_LIST"
			}
		}
	case 401:
		result.Permissions = "REQUIRES_AUTH"
	case 403:
		result.Permissions = "PRIVATE"
	case 404:
		return nil, nil // Bucket doesn't exist
	default:
		result.Permissions = "UNKNOWN"
	}

	return result, nil
}

// CheckPublicAccess uses allUsers/allAuthenticatedUsers IAM check
func (p *GCSProviderV2) CheckPublicAccess(bucketName string) *GCSAccessResult {
	result := &GCSAccessResult{
		BucketName: bucketName,
	}

	// Check IAM policy (if accessible)
	iamURL := fmt.Sprintf("https://storage.googleapis.com/storage/v1/b/%s/iam", bucketName)
	body, err := p.httpClient.GetBody(iamURL)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	var policy GCSIAMPolicy
	if err := json.Unmarshal(body, &policy); err == nil {
		for _, binding := range policy.Bindings {
			for _, member := range binding.Members {
				if member == "allUsers" {
					result.PublicAccess = true
					result.PublicRoles = append(result.PublicRoles, binding.Role)
				}
				if member == "allAuthenticatedUsers" {
					result.AuthenticatedAccess = true
				}
			}
		}
	}

	return result
}

func extractGCSBucket(url string) string {
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "https://")

	// Path style: storage.googleapis.com/{bucket}
	if strings.HasPrefix(url, "storage.googleapis.com/") {
		path := strings.TrimPrefix(url, "storage.googleapis.com/")
		// Handle /storage/v1/b/{bucket} format
		if strings.HasPrefix(path, "storage/v1/b/") {
			path = strings.TrimPrefix(path, "storage/v1/b/")
		}
		parts := strings.Split(path, "/")
		if len(parts) > 0 && parts[0] != "" {
			return strings.Split(parts[0], "?")[0]
		}
	}

	// Virtual-hosted: {bucket}.storage.googleapis.com
	if strings.Contains(url, ".storage.googleapis.com") {
		parts := strings.Split(url, ".storage.googleapis.com")
		if len(parts) > 0 {
			return parts[0]
		}
	}

	return ""
}

// GCSAccessResult holds IAM analysis
type GCSAccessResult struct {
	BucketName          string
	PublicAccess        bool
	AuthenticatedAccess bool
	PublicRoles         []string
	Error               string
}

type GCSIAMPolicy struct {
	Bindings []GCSBinding `json:"bindings"`
}

type GCSBinding struct {
	Role    string   `json:"role"`
	Members []string `json:"members"`
}

type GCSObjectList struct {
	Items []GCSObject `json:"items"`
}

type GCSObject struct {
	Name    string `json:"name"`
	Size    string `json:"size"`
	Updated string `json:"updated"`
}

func parseGCSJSON(body []byte) []string {
	var result GCSObjectList
	if err := json.Unmarshal(body, &result); err != nil {
		return nil
	}

	var files []string
	for i, obj := range result.Items {
		if i >= 10 {
			break
		}
		files = append(files, fmt.Sprintf("%s (%s bytes)", obj.Name, obj.Size))
	}
	return files
}
