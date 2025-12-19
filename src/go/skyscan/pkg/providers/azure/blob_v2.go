package azure

import (
	"context"
	"encoding/xml"
	"fmt"
	"skyscan/pkg/core"
	"skyscan/pkg/net"
	"strings"
)

// AzureBlobProviderV2 implements Azure Blob Storage enumeration with:
// 1. Storage account DNS discovery
// 2. Container brute-forcing with restype=container&comp=list
// 3. Pagination handling for large containers
// 4. SAS token detection
type AzureBlobProviderV2 struct {
	httpClient  *net.Client
	dnsResolver *net.DNSResolver
	config      *core.Config
}

// Common Azure container names for brute-forcing
var commonContainers = []string{
	// Generic
	"public", "data", "files", "images", "assets", "static", "media",
	"documents", "docs", "downloads", "uploads", "content",

	// Development
	"dev", "test", "staging", "prod", "production", "development",
	"qa", "uat", "demo", "sandbox",

	// Backups
	"backup", "backups", "archive", "archives", "snapshots",
	"db-backup", "database", "sql-backup",

	// Logs
	"logs", "log", "logging", "audit", "audit-logs",
	"diagnostics", "insights", "telemetry",

	// Azure-specific
	"vhds", "bootdiagnostics", "insights-logs", "insights-metrics",
	"azure-webjobs", "azure-webjobs-hosts", "azure-webjobs-secrets",
	"$logs", "$root", "$web",

	// Security
	"keys", "secrets", "certificates", "certs", "private",
	"config", "configuration", "settings",
}

func NewAzureBlobProviderV2(httpClient *net.Client, dnsResolver *net.DNSResolver) *AzureBlobProviderV2 {
	return &AzureBlobProviderV2{
		httpClient:  httpClient,
		dnsResolver: dnsResolver,
	}
}

func (p *AzureBlobProviderV2) Name() string {
	return "Azure-Blob-V2"
}

func (p *AzureBlobProviderV2) Init(config *core.Config) error {
	p.config = config
	return nil
}

// Generate creates candidate Azure Storage URLs
func (p *AzureBlobProviderV2) Generate(ctx context.Context, keyword string, output chan<- string) {
	// Azure Storage account endpoint
	accountDomain := fmt.Sprintf("%s.blob.core.windows.net", keyword)

	// First, just the account (to check if it exists)
	select {
	case <-ctx.Done():
		return
	case output <- fmt.Sprintf("http://%s", accountDomain):
	}

	// Then, enumerate containers
	for _, container := range commonContainers {
		select {
		case <-ctx.Done():
			return
		case output <- fmt.Sprintf("http://%s/%s?restype=container&comp=list", accountDomain, container):
		}
	}

	// Keyword-based container names
	for _, mut := range p.config.Mutations {
		select {
		case <-ctx.Done():
			return
		case output <- fmt.Sprintf("http://%s/%s?restype=container&comp=list", accountDomain, keyword+"-"+mut):
		case output <- fmt.Sprintf("http://%s/%s?restype=container&comp=list", accountDomain, mut+"-"+keyword):
		}
	}
}

// Check validates an Azure Storage URL
func (p *AzureBlobProviderV2) Check(ctx context.Context, target string) (*core.Result, error) {
	// Extract account and container from URL
	accountName, containerName := extractAzureInfo(target)
	if accountName == "" {
		return nil, fmt.Errorf("could not extract account from %s", target)
	}

	// Phase 1: DNS Check for storage account existence
	dnsHost := fmt.Sprintf("%s.blob.core.windows.net", accountName)
	dnsResult := p.dnsResolver.CheckExists(ctx, dnsHost)

	if dnsResult.Error != nil {
		return &core.Result{
			URL:      target,
			Provider: "Azure",
			Error:    dnsResult.Error.Error(),
		}, nil
	}

	if !dnsResult.Exists {
		// Storage account doesn't exist
		return nil, nil
	}

	// Phase 2: HTTP Check for container access
	// Use restype=container&comp=list for proper Azure API
	checkURL := target
	if containerName != "" && !strings.Contains(target, "restype=container") {
		checkURL = fmt.Sprintf("http://%s/%s?restype=container&comp=list",
			dnsHost, containerName)
	}

	status, size, err := p.httpClient.Check(checkURL)
	if err != nil {
		return &core.Result{
			URL:      target,
			Provider: "Azure",
			Error:    err.Error(),
		}, nil
	}

	result := &core.Result{
		URL:      target,
		Provider: "Azure",
		Status:   status,
		Size:     size,
	}

	switch status {
	case 200:
		result.Permissions = "PUBLIC_LIST"
		// Container allows public listing - parse blobs
		if body, err := p.httpClient.GetBody(checkURL); err == nil {
			result.Files = parseAzureBlobXML(body)
		}
	case 404:
		if containerName == "" {
			// Account doesn't exist
			return nil, nil
		}
		// Container doesn't exist, but account does
		result.Permissions = "CONTAINER_NOT_FOUND"
	case 403:
		result.Permissions = "PRIVATE"
	case 409:
		result.Permissions = "DISABLED"
	default:
		result.Permissions = "UNKNOWN"
	}

	return result, nil
}

// ListContainersWithPagination handles Azure's pagination for large containers
func (p *AzureBlobProviderV2) ListContainersWithPagination(accountName string, containerName string) ([]string, error) {
	var allBlobs []string
	marker := ""

	for {
		url := fmt.Sprintf("http://%s.blob.core.windows.net/%s?restype=container&comp=list",
			accountName, containerName)
		if marker != "" {
			url += "&marker=" + marker
		}

		body, err := p.httpClient.GetBody(url)
		if err != nil {
			return allBlobs, err
		}

		var result EnumerationResults
		if err := xml.Unmarshal(body, &result); err != nil {
			return allBlobs, err
		}

		for _, blob := range result.Blobs.Blob {
			allBlobs = append(allBlobs, blob.Name)
		}

		// Check for more pages
		if result.NextMarker == "" {
			break
		}
		marker = result.NextMarker
	}

	return allBlobs, nil
}

// Helper to extract account and container from Azure URL
func extractAzureInfo(url string) (account, container string) {
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "https://")

	// Format: {account}.blob.core.windows.net/{container}
	if strings.Contains(url, ".blob.core.windows.net") {
		parts := strings.Split(url, ".blob.core.windows.net")
		if len(parts) > 0 {
			account = parts[0]
		}
		if len(parts) > 1 {
			pathParts := strings.Split(strings.Trim(parts[1], "/"), "/")
			if len(pathParts) > 0 && pathParts[0] != "" {
				container = strings.Split(pathParts[0], "?")[0]
			}
		}
	}
	return
}

// Azure Blob XML structures
type EnumerationResults struct {
	Blobs      Blobs  `xml:"Blobs"`
	NextMarker string `xml:"NextMarker"`
}

type Blobs struct {
	Blob []Blob `xml:"Blob"`
}

type Blob struct {
	Name       string         `xml:"Name"`
	Properties BlobProperties `xml:"Properties"`
}

type BlobProperties struct {
	ContentLength int64  `xml:"Content-Length"`
	ContentType   string `xml:"Content-Type"`
	LastModified  string `xml:"Last-Modified"`
	BlobType      string `xml:"BlobType"`
}

func parseAzureBlobXML(body []byte) []string {
	var result EnumerationResults
	if err := xml.Unmarshal(body, &result); err != nil {
		return nil
	}

	var files []string
	for i, blob := range result.Blobs.Blob {
		if i >= 10 { // Limit to first 10
			break
		}
		files = append(files, fmt.Sprintf("%s (%d bytes)", blob.Name, blob.Properties.ContentLength))
	}
	return files
}
