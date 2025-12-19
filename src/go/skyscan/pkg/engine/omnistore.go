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
	awsprovider "skyscan/pkg/providers/aws"
	azureprovider "skyscan/pkg/providers/azure"
	gcpprovider "skyscan/pkg/providers/gcp"
	"sync"
	"sync/atomic"
	"time"
)

// OmniStore is the unified cloud storage enumeration engine.
// It coordinates all providers, manages concurrency, and handles output.
type OmniStore struct {
	config      *core.Config
	httpClient  *net.Client
	dnsResolver *net.DNSResolver
	netMapper   *netmapper.NetMapper
	permuter    *permute.PermuteCore

	// Providers
	s3Provider    *awsprovider.S3ProviderV2
	azureProvider *azureprovider.AzureBlobProviderV2
	gcsProvider   *gcpprovider.GCSProviderV2

	// Stats
	checked   atomic.Int64
	found     atomic.Int64
	startTime time.Time
}

// NewOmniStore creates a new unified storage enumeration engine
func NewOmniStore(config *core.Config) *OmniStore {
	httpClient := net.NewClient(config.Timeout)
	dnsResolver := net.NewDNSResolver(config.Resolvers, config.Timeout)
	netMapper := netmapper.NewNetMapper()
	permuter := permute.NewPermuteCore()

	return &OmniStore{
		config:        config,
		httpClient:    httpClient,
		dnsResolver:   dnsResolver,
		netMapper:     netMapper,
		permuter:      permuter,
		s3Provider:    awsprovider.NewS3ProviderV2(httpClient, dnsResolver),
		azureProvider: azureprovider.NewAzureBlobProviderV2(httpClient, dnsResolver),
		gcsProvider:   gcpprovider.NewGCSProviderV2(httpClient, dnsResolver),
	}
}

// ScanResult represents a unified finding across all providers
type ScanResult struct {
	Provider    string               `json:"provider"`
	URL         string               `json:"url"`
	Status      int                  `json:"status"`
	Permissions string               `json:"permissions"`
	Files       []string             `json:"files,omitempty"`
	Region      string               `json:"region,omitempty"`
	CloudInfo   *netmapper.CloudInfo `json:"cloud_info,omitempty"`
	Timestamp   string               `json:"timestamp"`
}

// Scan performs comprehensive multi-cloud storage enumeration
func (o *OmniStore) Scan(ctx context.Context, keyword string, outputPath string) error {
	o.startTime = time.Now()
	results := make(chan *ScanResult, 1000)
	var wg sync.WaitGroup

	// Initialize providers
	o.s3Provider.Init(o.config)
	o.azureProvider.Init(o.config)
	o.gcsProvider.Init(o.config)

	// Open output file if specified
	var outputFile *os.File
	var encoder *json.Encoder
	if outputPath != "" {
		var err error
		outputFile, err = os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer outputFile.Close()
		encoder = json.NewEncoder(outputFile)
	}

	// Start result collector
	var allResults []*ScanResult
	done := make(chan bool)
	go func() {
		for result := range results {
			// Print to console
			fmt.Printf("[%s] %s - %s (%d)\n",
				result.Provider, result.URL, result.Permissions, result.Status)

			// Write to file if specified
			if encoder != nil {
				encoder.Encode(result)
			}

			allResults = append(allResults, result)
			o.found.Add(1)
		}
		done <- true
	}()

	// Generate permutations
	mutations := o.permuter.GenerateAdvanced(keyword)
	fmt.Printf("[*] Generated %d mutation candidates for '%s'\n", len(mutations), keyword)

	// Add base keyword
	mutations = append([]string{keyword}, mutations...)

	// Create work channels
	s3Work := make(chan string, len(mutations))
	azureWork := make(chan string, len(mutations))
	gcsWork := make(chan string, len(mutations))

	// Distribute work
	for _, mut := range mutations {
		s3Work <- fmt.Sprintf("http://%s.s3.amazonaws.com", mut)
		azureWork <- fmt.Sprintf("http://%s.blob.core.windows.net", mut)
		gcsWork <- fmt.Sprintf("http://storage.googleapis.com/%s", mut)
	}
	close(s3Work)
	close(azureWork)
	close(gcsWork)

	// Launch S3 workers
	for i := 0; i < o.config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range s3Work {
				select {
				case <-ctx.Done():
					return
				default:
				}

				result, err := o.s3Provider.Check(ctx, url)
				o.checked.Add(1)

				if err == nil && result != nil {
					results <- &ScanResult{
						Provider:    result.Provider,
						URL:         result.URL,
						Status:      result.Status,
						Permissions: result.Permissions,
						Files:       result.Files,
						Timestamp:   time.Now().Format(time.RFC3339),
					}

					// Feedback loop: learn from discovery
					newCandidates := o.permuter.LearnFromDiscovery(result.URL)
					for _, candidate := range newCandidates {
						// Queue new candidates (non-blocking)
						select {
						case s3Work <- fmt.Sprintf("http://%s.s3.amazonaws.com", candidate):
						default:
						}
					}
				}
			}
		}()
	}

	// Launch Azure workers
	for i := 0; i < o.config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range azureWork {
				select {
				case <-ctx.Done():
					return
				default:
				}

				result, err := o.azureProvider.Check(ctx, url)
				o.checked.Add(1)

				if err == nil && result != nil {
					results <- &ScanResult{
						Provider:    result.Provider,
						URL:         result.URL,
						Status:      result.Status,
						Permissions: result.Permissions,
						Files:       result.Files,
						Timestamp:   time.Now().Format(time.RFC3339),
					}
				}
			}
		}()
	}

	// Launch GCS workers
	for i := 0; i < o.config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range gcsWork {
				select {
				case <-ctx.Done():
					return
				default:
				}

				result, err := o.gcsProvider.Check(ctx, url)
				o.checked.Add(1)

				if err == nil && result != nil {
					results <- &ScanResult{
						Provider:    result.Provider,
						URL:         result.URL,
						Status:      result.Status,
						Permissions: result.Permissions,
						Files:       result.Files,
						Timestamp:   time.Now().Format(time.RFC3339),
					}
				}
			}
		}()
	}

	// Wait for all workers to finish
	wg.Wait()
	close(results)
	<-done

	// Print summary
	elapsed := time.Since(o.startTime)
	fmt.Printf("\n[*] Scan Complete\n")
	fmt.Printf("    Checked: %d\n", o.checked.Load())
	fmt.Printf("    Found: %d\n", o.found.Load())
	fmt.Printf("    Duration: %s\n", elapsed.Round(time.Millisecond))
	fmt.Printf("    Rate: %.2f checks/sec\n", float64(o.checked.Load())/elapsed.Seconds())

	return nil
}

// ScanMultiple scans multiple keywords concurrently
func (o *OmniStore) ScanMultiple(ctx context.Context, keywords []string, outputPath string) error {
	for _, keyword := range keywords {
		if err := o.Scan(ctx, keyword, outputPath); err != nil {
			return err
		}
	}
	return nil
}

// GetStats returns current scan statistics
func (o *OmniStore) GetStats() map[string]interface{} {
	elapsed := time.Since(o.startTime)
	return map[string]interface{}{
		"checked":   o.checked.Load(),
		"found":     o.found.Load(),
		"elapsed":   elapsed.String(),
		"rate":      float64(o.checked.Load()) / elapsed.Seconds(),
		"netmapper": o.netMapper.GetStats(),
	}
}
