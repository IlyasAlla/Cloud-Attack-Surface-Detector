package permute

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PermuteCore implements intelligent, feedback-driven mutation generation.
// Unlike static wordlists, it learns patterns from discoveries and generates
// new candidates dynamically.
type PermuteCore struct {
	baseMutations []string
	regionHints   map[string]int // Track discovered regions
	patternHints  map[string]int // Track discovered patterns
	yearHints     []string       // Track discovered years
	mu            sync.RWMutex
	outputChan    chan string
}

// Patterns we look for in discovered names
var (
	datePattern   = regexp.MustCompile(`\d{4}[-_]?\d{2}[-_]?\d{2}`)
	yearPattern   = regexp.MustCompile(`\b(20\d{2})\b`)
	envPattern    = regexp.MustCompile(`(?i)(prod|dev|staging|test|qa|uat|demo)`)
	regionPattern = regexp.MustCompile(`(?i)(us-east|us-west|eu-west|eu-central|ap-south|ap-northeast)[-_]?\d?`)
)

// NewPermuteCore creates a new intelligent mutation engine
func NewPermuteCore() *PermuteCore {
	return &PermuteCore{
		baseMutations: getDefaultMutations(),
		regionHints:   make(map[string]int),
		patternHints:  make(map[string]int),
		yearHints:     []string{},
		outputChan:    make(chan string, 10000),
	}
}

// GetMutations returns the current set of mutations
func (p *PermuteCore) GetMutations() []string {
	return p.baseMutations
}

// LearnFromDiscovery analyzes a found asset and extracts patterns
func (p *PermuteCore) LearnFromDiscovery(name string) []string {
	p.mu.Lock()
	defer p.mu.Unlock()

	var newCandidates []string

	// Extract and learn from years
	if matches := yearPattern.FindAllString(name, -1); len(matches) > 0 {
		for _, year := range matches {
			// Generate adjacent years
			if y, err := strconv.Atoi(year); err == nil {
				newCandidates = append(newCandidates,
					strings.Replace(name, year, strconv.Itoa(y-1), 1),
					strings.Replace(name, year, strconv.Itoa(y+1), 1),
					strings.Replace(name, year, strconv.Itoa(y+2), 1),
				)
				p.yearHints = append(p.yearHints, year)
			}
		}
	}

	// Extract and learn from environments
	if matches := envPattern.FindAllString(name, -1); len(matches) > 0 {
		for _, env := range matches {
			env = strings.ToLower(env)
			p.patternHints[env]++

			// Generate other environment variants
			envs := []string{"prod", "dev", "staging", "test", "qa", "uat", "demo", "sandbox"}
			for _, newEnv := range envs {
				if newEnv != env {
					newCandidates = append(newCandidates,
						strings.Replace(strings.ToLower(name), env, newEnv, 1))
				}
			}
		}
	}

	// Extract and learn from regions
	if matches := regionPattern.FindAllString(name, -1); len(matches) > 0 {
		for _, region := range matches {
			region = strings.ToLower(region)
			p.regionHints[region]++

			// Generate other region variants
			regions := []string{
				"us-east-1", "us-east-2", "us-west-1", "us-west-2",
				"eu-west-1", "eu-west-2", "eu-central-1",
				"ap-south-1", "ap-northeast-1", "ap-southeast-1",
			}
			for _, newRegion := range regions {
				if newRegion != region {
					newCandidates = append(newCandidates,
						strings.Replace(strings.ToLower(name), region, newRegion, 1))
				}
			}
		}
	}

	// Learn component patterns (e.g., "company-service-env")
	parts := strings.FieldsFunc(name, func(r rune) bool {
		return r == '-' || r == '_' || r == '.'
	})

	if len(parts) >= 2 {
		// Store pattern template
		pattern := make([]string, len(parts))
		for i := range parts {
			pattern[i] = "{" + strconv.Itoa(i) + "}"
		}
		p.patternHints[strings.Join(pattern, "-")]++
	}

	return newCandidates
}

// Generate creates permutations for a keyword with feedback-driven intelligence
func (p *PermuteCore) Generate(ctx context.Context, keyword string, output chan<- string) {
	// Base keyword
	select {
	case <-ctx.Done():
		return
	case output <- keyword:
	}

	// Standard mutations
	for _, mut := range p.baseMutations {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Suffix variations
		output <- keyword + mut
		output <- keyword + "-" + mut
		output <- keyword + "_" + mut
		output <- keyword + "." + mut

		// Prefix variations
		output <- mut + keyword
		output <- mut + "-" + keyword
		output <- mut + "_" + keyword
	}

	// Apply learned hints
	p.mu.RLock()

	// Region-based permutations (prioritize frequently seen regions)
	topRegions := p.getTopHints(p.regionHints, 5)
	for _, region := range topRegions {
		output <- keyword + "-" + region
		output <- region + "-" + keyword
	}

	// Year-based permutations
	currentYear := time.Now().Year()
	years := []int{currentYear - 2, currentYear - 1, currentYear, currentYear + 1}
	for _, year := range years {
		y := strconv.Itoa(year)
		output <- keyword + "-" + y
		output <- keyword + "_" + y
		output <- keyword + y
	}

	p.mu.RUnlock()
}

// GenerateAdvanced creates comprehensive permutations with all techniques
func (p *PermuteCore) GenerateAdvanced(keyword string) []string {
	var results []string

	// 1. Case variations
	results = append(results,
		strings.ToLower(keyword),
		strings.ToUpper(keyword),
		strings.Title(strings.ToLower(keyword)),
	)

	// 2. Common prefix/suffix with separators
	for _, mut := range p.baseMutations {
		for _, sep := range []string{"", "-", "_", "."} {
			results = append(results,
				keyword+sep+mut,
				mut+sep+keyword,
			)
		}
	}

	// 3. Number sequences
	for i := 1; i <= 10; i++ {
		results = append(results,
			keyword+strconv.Itoa(i),
			keyword+"-"+strconv.Itoa(i),
			keyword+"0"+strconv.Itoa(i),
		)
	}

	// 4. Common cloud patterns
	cloudPatterns := []string{
		"%s-bucket",
		"%s-storage",
		"%s-data",
		"%s-backup",
		"%s-assets",
		"%s-static",
		"%s-cdn",
		"%s-logs",
		"bucket-%s",
		"storage-%s",
		"data-%s",
	}
	for _, pattern := range cloudPatterns {
		results = append(results, strings.ReplaceAll(pattern, "%s", keyword))
	}

	// 5. Environment combinations
	envs := []string{"prod", "production", "dev", "development", "staging", "test", "qa", "uat"}
	for _, env := range envs {
		results = append(results,
			keyword+"-"+env,
			env+"-"+keyword,
			keyword+"."+env,
		)
	}

	// 6. Year combinations
	currentYear := time.Now().Year()
	for y := currentYear - 3; y <= currentYear+1; y++ {
		year := strconv.Itoa(y)
		results = append(results,
			keyword+"-"+year,
			keyword+year,
			keyword+"-"+year[2:], // Short year
		)
	}

	// 7. Region combinations (AWS/Azure/GCP)
	regions := []string{
		"us-east-1", "us-west-2", "eu-west-1", "eu-central-1",
		"ap-south-1", "ap-northeast-1",
		"eastus", "westus", "westeurope", // Azure
		"us-central1", "europe-west1", // GCP
	}
	for _, region := range regions {
		results = append(results,
			keyword+"-"+region,
			region+"-"+keyword,
		)
	}

	return uniqueStrings(results)
}

// getTopHints returns the most frequently seen hints
func (p *PermuteCore) getTopHints(hints map[string]int, limit int) []string {
	type kv struct {
		Key   string
		Value int
	}

	var sorted []kv
	for k, v := range hints {
		sorted = append(sorted, kv{k, v})
	}

	// Simple bubble sort for small lists
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].Value > sorted[i].Value {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	var results []string
	for i := 0; i < len(sorted) && i < limit; i++ {
		results = append(results, sorted[i].Key)
	}
	return results
}

func getDefaultMutations() []string {
	return []string{
		// Environments
		"prod", "production", "dev", "development", "staging", "stage",
		"test", "testing", "qa", "uat", "demo", "sandbox", "beta", "alpha",
		"live", "preview", "internal", "external", "public", "private",

		// Functions
		"backup", "backups", "bak", "archive", "archives", "old",
		"logs", "log", "logging", "audit", "data", "db", "database",
		"assets", "static", "media", "images", "img", "files", "docs",
		"documents", "downloads", "uploads", "tmp", "temp", "cache",
		"config", "configs", "configuration", "settings",

		// Infrastructure
		"web", "api", "app", "apps", "www", "cdn", "edge",
		"storage", "store", "bucket", "blob", "s3", "gcs", "azure",
		"aws", "cloud", "infra", "infrastructure",

		// Security-relevant
		"secrets", "secret", "keys", "key", "cert", "certs", "certificates",
		"private", "confidential", "restricted", "admin", "root",
		"credentials", "creds", "tokens", "auth", "authentication",

		// Misc
		"v1", "v2", "v3", "new", "legacy", "deprecated",
		"main", "master", "primary", "secondary", "replica",
	}
}

func uniqueStrings(input []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, s := range input {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}
