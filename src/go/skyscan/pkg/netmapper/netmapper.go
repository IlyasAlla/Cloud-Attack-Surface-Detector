package netmapper

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
)

// NetMapper provides high-performance IP-to-Cloud attribution using
// a trie-based data structure for O(log n) lookups.
// This is significantly faster than Python's netaddr for high-volume scans.
type NetMapper struct {
	aws   *IPTrie
	azure *IPTrie
	gcp   *IPTrie
	mu    sync.RWMutex
}

// CloudInfo contains metadata about a cloud IP range
type CloudInfo struct {
	Provider    string `json:"provider"`
	Service     string `json:"service"`
	Region      string `json:"region"`
	NetworkType string `json:"network_type"` // e.g., EC2, CloudFront, Lambda
	CIDR        string `json:"cidr"`
}

// NewNetMapper creates a new high-performance cloud IP mapper
func NewNetMapper() *NetMapper {
	return &NetMapper{
		aws:   NewIPTrie(),
		azure: NewIPTrie(),
		gcp:   NewIPTrie(),
	}
}

// LoadFromDirectory loads all cloud IP ranges from JSON files
func (m *NetMapper) LoadFromDirectory(dataDir string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Load AWS
	if err := m.loadAWS(dataDir + "/aws_cloud.json"); err != nil {
		fmt.Printf("[!] Failed to load AWS ranges: %v\n", err)
	}

	// Load Azure
	if err := m.loadAzure(dataDir + "/azure_cloud.json"); err != nil {
		fmt.Printf("[!] Failed to load Azure ranges: %v\n", err)
	}

	// Load GCP
	if err := m.loadGCP(dataDir + "/gcp_cloud.json"); err != nil {
		fmt.Printf("[!] Failed to load GCP ranges: %v\n", err)
	}

	return nil
}

// Lookup finds the cloud provider and metadata for an IP address
func (m *NetMapper) Lookup(ipStr string) *CloudInfo {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	// Check each provider (order by typical frequency)
	if info := m.aws.Lookup(ip); info != nil {
		return info
	}
	if info := m.azure.Lookup(ip); info != nil {
		return info
	}
	if info := m.gcp.Lookup(ip); info != nil {
		return info
	}

	return nil
}

// BatchLookup performs concurrent lookups for multiple IPs
func (m *NetMapper) BatchLookup(ips []string) map[string]*CloudInfo {
	results := make(map[string]*CloudInfo, len(ips))
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, ip := range ips {
		wg.Add(1)
		go func(ipStr string) {
			defer wg.Done()
			info := m.Lookup(ipStr)
			mu.Lock()
			results[ipStr] = info
			mu.Unlock()
		}(ip)
	}

	wg.Wait()
	return results
}

// GetStats returns statistics about loaded ranges
func (m *NetMapper) GetStats() map[string]int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]int{
		"aws_ranges":   m.aws.Count(),
		"azure_ranges": m.azure.Count(),
		"gcp_ranges":   m.gcp.Count(),
	}
}

// loadAWS parses AWS IP ranges JSON
func (m *NetMapper) loadAWS(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var awsData struct {
		Prefixes []struct {
			IPPrefix           string `json:"ip_prefix"`
			Region             string `json:"region"`
			Service            string `json:"service"`
			NetworkBorderGroup string `json:"network_border_group"`
		} `json:"prefixes"`
		IPv6Prefixes []struct {
			IPv6Prefix         string `json:"ipv6_prefix"`
			Region             string `json:"region"`
			Service            string `json:"service"`
			NetworkBorderGroup string `json:"network_border_group"`
		} `json:"ipv6_prefixes"`
	}

	if err := json.Unmarshal(data, &awsData); err != nil {
		return err
	}

	for _, p := range awsData.Prefixes {
		m.aws.Insert(p.IPPrefix, &CloudInfo{
			Provider:    "AWS",
			Service:     p.Service,
			Region:      p.Region,
			NetworkType: p.NetworkBorderGroup,
			CIDR:        p.IPPrefix,
		})
	}

	for _, p := range awsData.IPv6Prefixes {
		m.aws.Insert(p.IPv6Prefix, &CloudInfo{
			Provider:    "AWS",
			Service:     p.Service,
			Region:      p.Region,
			NetworkType: p.NetworkBorderGroup,
			CIDR:        p.IPv6Prefix,
		})
	}

	fmt.Printf("[+] Loaded %d AWS IP ranges\n", len(awsData.Prefixes)+len(awsData.IPv6Prefixes))
	return nil
}

// loadAzure parses Azure IP ranges JSON
func (m *NetMapper) loadAzure(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var azureData struct {
		Values []struct {
			Name       string `json:"name"`
			ID         string `json:"id"`
			Properties struct {
				Region          string   `json:"region"`
				Platform        string   `json:"platform"`
				SystemService   string   `json:"systemService"`
				AddressPrefixes []string `json:"addressPrefixes"`
			} `json:"properties"`
		} `json:"values"`
	}

	if err := json.Unmarshal(data, &azureData); err != nil {
		return err
	}

	count := 0
	for _, v := range azureData.Values {
		for _, prefix := range v.Properties.AddressPrefixes {
			m.azure.Insert(prefix, &CloudInfo{
				Provider:    "Azure",
				Service:     v.Properties.SystemService,
				Region:      v.Properties.Region,
				NetworkType: v.Properties.Platform,
				CIDR:        prefix,
			})
			count++
		}
	}

	fmt.Printf("[+] Loaded %d Azure IP ranges\n", count)
	return nil
}

// loadGCP parses GCP IP ranges JSON
func (m *NetMapper) loadGCP(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var gcpData struct {
		Prefixes []struct {
			IPv4Prefix string `json:"ipv4Prefix"`
			IPv6Prefix string `json:"ipv6Prefix"`
			Service    string `json:"service"`
			Scope      string `json:"scope"`
		} `json:"prefixes"`
	}

	if err := json.Unmarshal(data, &gcpData); err != nil {
		return err
	}

	count := 0
	for _, p := range gcpData.Prefixes {
		if p.IPv4Prefix != "" {
			m.gcp.Insert(p.IPv4Prefix, &CloudInfo{
				Provider:    "GCP",
				Service:     p.Service,
				Region:      p.Scope,
				NetworkType: "Google Cloud",
				CIDR:        p.IPv4Prefix,
			})
			count++
		}
		if p.IPv6Prefix != "" {
			m.gcp.Insert(p.IPv6Prefix, &CloudInfo{
				Provider:    "GCP",
				Service:     p.Service,
				Region:      p.Scope,
				NetworkType: "Google Cloud",
				CIDR:        p.IPv6Prefix,
			})
			count++
		}
	}

	fmt.Printf("[+] Loaded %d GCP IP ranges\n", count)
	return nil
}

// IPTrie implements a radix trie for efficient CIDR matching
type IPTrie struct {
	root  *TrieNode
	count int
}

type TrieNode struct {
	children [2]*TrieNode
	info     *CloudInfo
}

func NewIPTrie() *IPTrie {
	return &IPTrie{
		root: &TrieNode{},
	}
}

func (t *IPTrie) Count() int {
	return t.count
}

// Insert adds a CIDR range to the trie
func (t *IPTrie) Insert(cidr string, info *CloudInfo) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return
	}

	bits := ipToBits(ipnet.IP)
	ones, _ := ipnet.Mask.Size()

	node := t.root
	for i := 0; i < ones; i++ {
		bit := (bits[i/8] >> (7 - i%8)) & 1
		if node.children[bit] == nil {
			node.children[bit] = &TrieNode{}
		}
		node = node.children[bit]
	}
	node.info = info
	t.count++
}

// Lookup finds the longest prefix match for an IP
func (t *IPTrie) Lookup(ip net.IP) *CloudInfo {
	// Normalize to 16 bytes
	ip = ip.To16()
	if ip == nil {
		return nil
	}

	// Handle IPv4 (use last 4 bytes)
	isIPv4 := strings.Contains(ip.String(), ".")
	var bits []byte
	if isIPv4 {
		ip4 := ip.To4()
		if ip4 != nil {
			bits = ip4
		} else {
			bits = ip[12:16]
		}
	} else {
		bits = ip
	}

	var lastMatch *CloudInfo
	node := t.root

	maxBits := len(bits) * 8
	for i := 0; i < maxBits; i++ {
		if node.info != nil {
			lastMatch = node.info
		}

		bit := (bits[i/8] >> (7 - i%8)) & 1
		if node.children[bit] == nil {
			break
		}
		node = node.children[bit]
	}

	// Check final node
	if node.info != nil {
		lastMatch = node.info
	}

	return lastMatch
}

func ipToBits(ip net.IP) []byte {
	// Use IPv4 if possible
	if ip4 := ip.To4(); ip4 != nil {
		return ip4
	}
	return ip.To16()
}
