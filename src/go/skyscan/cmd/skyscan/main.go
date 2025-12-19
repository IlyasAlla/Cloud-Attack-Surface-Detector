package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"skyscan/pkg/core"
	"skyscan/pkg/engine"
	"strings"
	"syscall"
	"time"
)

const banner = `
╔═══════════════════════════════════════════════════════════════╗
║     ███████╗██╗  ██╗██╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██║
║     ██╔════╝██║ ██╔╝╚██╗ ██╔╝██╔════╝██╔════╝██╔══██╗████╗  ██║
║     ███████╗█████╔╝  ╚████╔╝ ███████╗██║     ███████║██╔██╗ ██║
║     ╚════██║██╔═██╗   ╚██╔╝  ╚════██║██║     ██╔══██║██║╚██╗██║
║     ███████║██║  ██╗   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
║     ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══║
║                                                               ║
║         ️  Ultimate Cloud Attack Surface Scanner ️          ║
║                    100+ Cloud Services                        ║
║           AWS • Azure • GCP • DigitalOcean • More            ║
╚═══════════════════════════════════════════════════════════════╝
`

func main() {
	// Define flags
	keyword := flag.String("k", "", "Target keyword (company name, project name)")
	keywordFile := flag.String("kf", "", "File with keywords (one per line)")
	output := flag.String("o", "", "Output file path (JSON)")
	threads := flag.Int("t", 50, "Number of concurrent threads")
	timeout := flag.Int("timeout", 10, "Request timeout in seconds")
	resolvers := flag.String("r", "", "Custom DNS resolvers (comma-separated)")
	mutations := flag.String("m", "", "Additional mutations (comma-separated)")
	jsonOutput := flag.Bool("json", false, "JSON output only (no banner)")
	silent := flag.Bool("s", false, "Silent mode (minimal output)")
	help := flag.Bool("h", false, "Show help")

	// Legacy flag compatibility
	legacyKeyword := flag.String("keyword", "", "Legacy: Target keyword")

	flag.Parse()

	// Support legacy flag
	if *keyword == "" && *legacyKeyword != "" {
		*keyword = *legacyKeyword
	}

	if *help || (*keyword == "" && *keywordFile == "") {
		printHelp()
		return
	}

	// Print banner unless JSON mode
	if !*jsonOutput && !*silent {
		fmt.Println(banner)
	}

	// Build configuration
	config := &core.Config{
		Threads: *threads,
		Timeout: *timeout,
	}

	// Parse resolvers
	if *resolvers != "" {
		config.Resolvers = strings.Split(*resolvers, ",")
	}

	// Parse mutations (use defaults if not specified)
	if *mutations != "" {
		config.Mutations = strings.Split(*mutations, ",")
	} else {
		config.Mutations = getDefaultMutations()
	}

	// Collect keywords
	var keywords []string
	if *keyword != "" {
		keywords = append(keywords, *keyword)
	}
	if *keywordFile != "" {
		fileKeywords, err := readKeywordsFile(*keywordFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading keywords file: %v\n", err)
			os.Exit(1)
		}
		keywords = append(keywords, fileKeywords...)
	}

	// Setup context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n[!] Interrupted, shutting down...")
		cancel()
	}()

	// Create scanner
	scanner := engine.NewFullCloudRecon(config)

	// Run scan for each keyword
	startTime := time.Now()
	for _, kw := range keywords {
		if !*silent {
			fmt.Printf("[*] Scanning keyword: %s\n", kw)
		}

		outputPath := *output
		if outputPath != "" && len(keywords) > 1 {
			outputPath = fmt.Sprintf("%s_%s.json", strings.TrimSuffix(*output, ".json"), kw)
		}

		err := scanner.ScanAll(ctx, kw, outputPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
	}

	if !*silent {
		elapsed := time.Since(startTime)
		fmt.Printf("\n[*] Total time: %s\n", elapsed.Round(time.Millisecond))
	}
}

func printHelp() {
	fmt.Println(banner)
	fmt.Println(`
USAGE:
    skyscan -k <keyword> [options]
    skyscan -kf <keywords_file> [options]

OPTIONS:
    -k string        Target keyword (company name, project name)
    -kf string       File with keywords (one per line)
    -o string        Output file path (JSON)
    -t int           Number of concurrent threads (default: 50)
    -timeout int     Request timeout in seconds (default: 10)
    -r string        Custom DNS resolvers (comma-separated)
    -m string        Additional mutations (comma-separated)
    -json            JSON output only (no banner)
    -s               Silent mode (minimal output)
    -h               Show this help

EXAMPLES:
    # Basic scan
    skyscan -k acme-corp

    # Scan with output
    skyscan -k company -o results.json

    # Multiple keywords from file
    skyscan -kf targets.txt -o results.json

    # High-performance scan
    skyscan -k bigcorp -t 100 -timeout 5

    # Custom mutations
    skyscan -k company -m "prod,staging,backup,data"

DISCOVERED ASSETS:
     Storage      - S3, Azure Blob, GCS, DigitalOcean Spaces
    ️ Compute      - EC2, App Service, Cloud Run, Lambda
    ️ Databases    - RDS, CosmosDB, Cloud SQL, Redis
     APIs         - API Gateway, AppSync, Cloud Endpoints
     CDN          - CloudFront, Azure CDN, Cloud CDN
     Containers   - EKS, AKS, GKE, Container Registry
     Serverless   - Lambda, Functions, Cloud Functions
     Secrets      - Key Vault, Secrets Manager

SUPPORTED PROVIDERS:
    AWS, Azure, GCP, DigitalOcean, Heroku, Alibaba Cloud,
    Oracle Cloud, IBM Cloud, Netlify, Vercel, Cloudflare,
    Render, Railway, Fly.io
`)
}

func readKeywordsFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var keywords []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			keywords = append(keywords, line)
		}
	}
	return keywords, nil
}

func getDefaultMutations() []string {
	return []string{
		// Environments
		"prod", "production", "dev", "development", "staging",
		"test", "qa", "uat", "demo", "sandbox", "beta",

		// Functions
		"backup", "backups", "logs", "data", "assets",
		"static", "media", "images", "docs", "files",
		"config", "private", "public", "internal",

		// Infrastructure
		"api", "app", "web", "cdn", "db", "cache",
		"storage", "bucket", "archive", "temp",

		// Years (current and recent)
		"2024", "2025", "2023",

		// Numbers
		"1", "2", "01", "02",
	}
}

// Legacy JSON output for backwards compatibility
func outputJson(result interface{}) {
	jsonBytes, _ := json.Marshal(result)
	fmt.Println(string(jsonBytes))
}
