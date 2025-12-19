package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"skyscan/pkg/core"
	"skyscan/pkg/net"
	"skyscan/pkg/netmapper"
	"skyscan/pkg/permute"
	"skyscan/pkg/providers"
	awsprovider "skyscan/pkg/providers/aws"
	azureprovider "skyscan/pkg/providers/azure"
	gcpprovider "skyscan/pkg/providers/gcp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// FullCloudRecon is the comprehensive cloud reconnaissance engine
// that discovers ALL cloud assets, not just storage.
type FullCloudRecon struct {
	config      *core.Config
	httpClient  *net.Client
	dnsResolver *net.DNSResolver
	netMapper   *netmapper.NetMapper
	permuter    *permute.PermuteCore

	// Storage providers
	s3Provider    *awsprovider.S3ProviderV2
	azureProvider *azureprovider.AzureBlobProviderV2
	gcsProvider   *gcpprovider.GCSProviderV2

	// General cloud asset enumerator
	cloudEnumerator *providers.CloudAssetEnumerator

	// Stats
	checked   atomic.Int64
	found     atomic.Int64
	startTime time.Time
}

// FullCloudResult represents a unified result from any cloud service discovery
type FullCloudResult struct {
	URL         string   `json:"url"`
	Provider    string   `json:"provider"`
	ServiceType string   `json:"service_type"`
	Region      string   `json:"region,omitempty"`
	Status      int      `json:"status"`
	Permissions string   `json:"permissions,omitempty"`
	Severity    string   `json:"severity"`
	Accessible  bool     `json:"accessible"`
	Files       []string `json:"files,omitempty"`
	Timestamp   string   `json:"timestamp"`
	Category    string   `json:"category"` // storage, compute, database, api, cdn, etc.
}

// NewFullCloudRecon creates a new comprehensive cloud reconnaissance engine
func NewFullCloudRecon(config *core.Config) *FullCloudRecon {
	httpClient := net.NewClient(config.Timeout)
	dnsResolver := net.NewDNSResolver(config.Resolvers, config.Timeout)
	netMapper := netmapper.NewNetMapper()
	permuter := permute.NewPermuteCore()

	return &FullCloudRecon{
		config:          config,
		httpClient:      httpClient,
		dnsResolver:     dnsResolver,
		netMapper:       netMapper,
		permuter:        permuter,
		s3Provider:      awsprovider.NewS3ProviderV2(httpClient, dnsResolver),
		azureProvider:   azureprovider.NewAzureBlobProviderV2(httpClient, dnsResolver),
		gcsProvider:     gcpprovider.NewGCSProviderV2(httpClient, dnsResolver),
		cloudEnumerator: providers.NewCloudAssetEnumerator(httpClient, dnsResolver),
	}
}

// ScanAll performs comprehensive cloud reconnaissance
func (r *FullCloudRecon) ScanAll(ctx context.Context, keyword string, outputPath string) error {
	r.startTime = time.Now()
	results := make(chan *FullCloudResult, 10000)
	var wg sync.WaitGroup

	// Initialize all providers
	r.s3Provider.Init(r.config)
	r.azureProvider.Init(r.config)
	r.gcsProvider.Init(r.config)
	r.cloudEnumerator.Init(r.config)

	// Generate all mutations
	mutations := r.permuter.GenerateAdvanced(keyword)
	allKeywords := append([]string{keyword}, mutations...)

	fmt.Printf("\n[*]  Full Cloud Reconnaissance Starting\n")
	fmt.Printf("[*] Target: %s\n", keyword)
	fmt.Printf("[*] Mutations: %d\n", len(mutations))
	fmt.Printf("[*] Cloud Services: %d\n", len(providers.AllCloudServices))
	fmt.Printf("[*] Threads: %d\n", r.config.Threads)
	fmt.Println()

	// Open output file
	var outputFile *os.File
	var encoder *json.Encoder
	if outputPath != "" {
		var err error
		outputFile, err = os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("failed to create output: %w", err)
		}
		defer outputFile.Close()
		encoder = json.NewEncoder(outputFile)
	}

	// Collect results in background
	var allResults []*FullCloudResult
	done := make(chan bool)
	go func() {
		for result := range results {
			icon := ""
			switch result.Category {
			case "storage":
				icon = ""
			case "database":
				icon = "️"
			case "compute":
				icon = "️"
			case "api":
				icon = ""
			case "cdn":
				icon = ""
			case "container":
				icon = ""
			case "serverless":
				icon = ""
			}

			severity := result.Severity
			if severity == "CRITICAL" {
				severity = " CRITICAL"
			} else if severity == "HIGH" {
				severity = " HIGH"
			} else if severity == "MEDIUM" {
				severity = " MEDIUM"
			}

			fmt.Printf("%s [%s] %s - %s/%s (%d)\n",
				icon, severity, result.URL, result.Provider, result.ServiceType, result.Status)

			if encoder != nil {
				encoder.Encode(result)
			}

			allResults = append(allResults, result)
			r.found.Add(1)
		}
		done <- true
	}()

	// ===== PHASE 1: Storage Enumeration =====
	fmt.Println("[*] Phase 1/4: Storage Enumeration (S3, Azure Blob, GCS)...")
	wg.Add(1)
	go func() {
		defer wg.Done()
		r.scanStorage(ctx, allKeywords, results)
	}()

	// ===== PHASE 2: All Cloud Services =====
	fmt.Println("[*] Phase 2/4: Cloud Services Enumeration (100+ services)...")

	// Create work channel for cloud services
	cloudWork := make(chan providers.CloudTarget, 100000)

	// Generate all targets
	go func() {
		for _, kw := range allKeywords[:min(len(allKeywords), 50)] { // Limit keywords
			r.cloudEnumerator.GenerateAllTargets(ctx, kw, cloudWork)
		}
		close(cloudWork)
	}()

	// Launch cloud service workers
	for i := 0; i < r.config.Threads*2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range cloudWork {
				select {
				case <-ctx.Done():
					return
				default:
				}

				result := r.cloudEnumerator.CheckTarget(ctx, target)
				r.checked.Add(1)

				if result != nil && (result.Status == 200 || result.Status == 403 || result.Status == 401) {
					fullResult := &FullCloudResult{
						URL:         result.URL,
						Provider:    result.Provider,
						ServiceType: result.ServiceType,
						Region:      result.Region,
						Status:      result.Status,
						Severity:    result.Severity,
						Accessible:  result.Accessible,
						Timestamp:   time.Now().Format(time.RFC3339),
						Category:    categorizeService(result.ServiceType),
					}

					if result.Status == 403 || result.Status == 401 {
						fullResult.Permissions = "PROTECTED"
					} else if result.Status == 200 {
						fullResult.Permissions = "ACCESSIBLE"
					}

					results <- fullResult
				}
			}
		}()
	}

	wg.Wait()
	close(results)
	<-done

	// Print summary
	r.printSummary(allResults)

	return nil
}

// scanStorage handles S3, Azure Blob, and GCS bucket enumeration
func (r *FullCloudRecon) scanStorage(ctx context.Context, keywords []string, results chan<- *FullCloudResult) {
	var wg sync.WaitGroup

	// S3 workload
	s3Work := make(chan string, len(keywords)*3)
	for _, kw := range keywords {
		s3Work <- fmt.Sprintf("http://%s.s3.amazonaws.com", kw)
	}
	close(s3Work)

	for i := 0; i < r.config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range s3Work {
				result, err := r.s3Provider.Check(ctx, url)
				r.checked.Add(1)
				if err == nil && result != nil {
					results <- &FullCloudResult{
						URL:         result.URL,
						Provider:    result.Provider,
						ServiceType: "S3 Bucket",
						Status:      result.Status,
						Permissions: result.Permissions,
						Severity:    classifyStorageSeverity(result.Permissions),
						Accessible:  result.Status == 200,
						Files:       result.Files,
						Timestamp:   time.Now().Format(time.RFC3339),
						Category:    "storage",
					}
				}
			}
		}()
	}

	// Azure workload
	azureWork := make(chan string, len(keywords)*3)
	for _, kw := range keywords {
		azureWork <- fmt.Sprintf("http://%s.blob.core.windows.net", kw)
	}
	close(azureWork)

	for i := 0; i < r.config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range azureWork {
				result, err := r.azureProvider.Check(ctx, url)
				r.checked.Add(1)
				if err == nil && result != nil {
					results <- &FullCloudResult{
						URL:         result.URL,
						Provider:    result.Provider,
						ServiceType: "Blob Storage",
						Status:      result.Status,
						Permissions: result.Permissions,
						Severity:    classifyStorageSeverity(result.Permissions),
						Accessible:  result.Status == 200,
						Files:       result.Files,
						Timestamp:   time.Now().Format(time.RFC3339),
						Category:    "storage",
					}
				}
			}
		}()
	}

	// GCS workload
	gcsWork := make(chan string, len(keywords)*3)
	for _, kw := range keywords {
		gcsWork <- fmt.Sprintf("http://storage.googleapis.com/%s", kw)
	}
	close(gcsWork)

	for i := 0; i < r.config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range gcsWork {
				result, err := r.gcsProvider.Check(ctx, url)
				r.checked.Add(1)
				if err == nil && result != nil {
					results <- &FullCloudResult{
						URL:         result.URL,
						Provider:    result.Provider,
						ServiceType: "GCS Bucket",
						Status:      result.Status,
						Permissions: result.Permissions,
						Severity:    classifyStorageSeverity(result.Permissions),
						Accessible:  result.Status == 200,
						Files:       result.Files,
						Timestamp:   time.Now().Format(time.RFC3339),
						Category:    "storage",
					}
				}
			}
		}()
	}

	wg.Wait()
}

func (r *FullCloudRecon) printSummary(results []*FullCloudResult) {
	elapsed := time.Since(r.startTime)

	// Count by category
	categories := make(map[string]int)
	providers := make(map[string]int)
	severities := make(map[string]int)

	for _, res := range results {
		categories[res.Category]++
		providers[res.Provider]++
		severities[res.Severity]++
	}

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println(" RECONNAISSANCE SUMMARY")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("\n️  Duration: %s\n", elapsed.Round(time.Millisecond))
	fmt.Printf(" Checked: %d targets\n", r.checked.Load())
	fmt.Printf(" Found: %d assets\n", r.found.Load())
	fmt.Printf(" Rate: %.2f checks/sec\n", float64(r.checked.Load())/elapsed.Seconds())

	fmt.Println("\n By Category:")
	for cat, count := range categories {
		fmt.Printf("   %-15s %d\n", cat, count)
	}

	fmt.Println("\n️  By Provider:")
	for prov, count := range providers {
		fmt.Printf("   %-15s %d\n", prov, count)
	}

	fmt.Println("\n️  By Severity:")
	for sev, count := range severities {
		fmt.Printf("   %-15s %d\n", sev, count)
	}
	fmt.Println()
}

// Helper functions
func categorizeService(serviceType string) string {
	switch {
	case contains(serviceType, "S3", "Blob", "GCS", "OSS", "Spaces", "R2", "Object Storage"):
		return "storage"
	case contains(serviceType, "RDS", "SQL", "Cosmos", "Firestore", "DynamoDB", "Redis", "Cache", "Spanner", "BigQuery"):
		return "database"
	case contains(serviceType, "Lambda", "Functions", "Cloud Run", "App Engine", "Beanstalk", "App Service"):
		return "compute"
	case contains(serviceType, "API", "Gateway", "AppSync", "Endpoints"):
		return "api"
	case contains(serviceType, "CDN", "CloudFront", "Front Door", "Edge"):
		return "cdn"
	case contains(serviceType, "EKS", "AKS", "GKE", "Container", "ECR", "ACR"):
		return "container"
	case contains(serviceType, "Key Vault", "Secrets", "KMS"):
		return "secrets"
	default:
		return "other"
	}
}

func contains(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func classifyStorageSeverity(permissions string) string {
	switch permissions {
	case "PUBLIC_READ", "PUBLIC_LIST", "PUBLIC_WRITE":
		return "CRITICAL"
	case "AUTHENTICATED":
		return "HIGH"
	case "PROTECTED", "PRIVATE":
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
