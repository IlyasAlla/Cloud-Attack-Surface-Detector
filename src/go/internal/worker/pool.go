package worker

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

type Job struct {
	IP       string
	Hostname string
	Port     int
	Paths    []string
}

type Result struct {
	IP              string
	Port            int
	Open            bool
	Banner          string
	Headers         map[string]string
	Vulnerabilities []string
	SSLInfo         map[string]string
}

func Worker(jobs <-chan Job, results chan<- Result, wg *sync.WaitGroup, timeoutMs int) {
	defer wg.Done()
	timeout := time.Duration(timeoutMs) * time.Millisecond

	for job := range jobs {
		// Interesting paths to check
		interestingPaths := job.Paths
		if len(interestingPaths) == 0 {
			// Fallback if none provided
			interestingPaths = []string{"/.env", "/.git/HEAD", "/admin", "/robots.txt"}
		}

		// Resolve if not an IP
		targetHost := job.IP
		resolvedIP := job.IP

		if net.ParseIP(job.IP) == nil {
			ips, err := net.LookupIP(job.IP)
			if err == nil && len(ips) > 0 {
				resolvedIP = ips[0].String()
				targetHost = resolvedIP
			} else {
				// Could not resolve, skip
				results <- Result{IP: job.IP, Port: job.Port, Open: false}
				continue
			}
		}

		address := net.JoinHostPort(targetHost, fmt.Sprintf("%d", job.Port))

		conn, err := net.DialTimeout("tcp", address, timeout)

		if err == nil {
			// Banner Grabbing
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			buffer := make([]byte, 1024)
			n, _ := conn.Read(buffer)
			banner := string(buffer[:n])

			// Clean up banner
			if len(banner) > 0 {
				if len(banner) > 50 {
					banner = banner[:50] + "..."
				}
			}

			headers := make(map[string]string)
			vulns := []string{}
			sslInfo := make(map[string]string)

			// Web Analysis (HTTP/HTTPS)
			if job.Port == 80 || job.Port == 443 || job.Port == 8080 || job.Port == 8443 {
				scheme := "http"
				if job.Port == 443 || job.Port == 8443 {
					scheme = "https"
				}

				// Use Hostname for SNI if available, otherwise IP
				requestHost := job.IP
				if job.Hostname != "" {
					requestHost = job.Hostname
				}

				baseURL := fmt.Sprintf("%s://%s:%d", scheme, requestHost, job.Port)

				tr := &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				}
				client := &http.Client{
					Timeout:   2 * time.Second,
					Transport: tr,
				}

				// 1. Header Analysis & SSL
				resp, err := client.Head(baseURL)
				if err == nil {
					for k, v := range resp.Header {
						if len(v) > 0 {
							headers[k] = v[0]
						}
					}
					if val, ok := headers["Server"]; ok && banner == "" {
						banner = val
					}

					// Capture SSL Info
					if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
						cert := resp.TLS.PeerCertificates[0]
						sslInfo["Subject"] = cert.Subject.CommonName
						sslInfo["Issuer"] = cert.Issuer.CommonName
						sslInfo["Expires"] = cert.NotAfter.Format("2006-01-02")
						sslInfo["DNSNames"] = fmt.Sprintf("%v", cert.DNSNames)

						// Improved Version Mapping
						switch resp.TLS.Version {
						case tls.VersionTLS10:
							sslInfo["Version"] = "TLS 1.0"
						case tls.VersionTLS11:
							sslInfo["Version"] = "TLS 1.1"
						case tls.VersionTLS12:
							sslInfo["Version"] = "TLS 1.2"
						case tls.VersionTLS13:
							sslInfo["Version"] = "TLS 1.3"
						default:
							sslInfo["Version"] = fmt.Sprintf("Unknown (%x)", resp.TLS.Version)
						}

						// Improved Cipher Suite
						sslInfo["CipherSuite"] = tls.CipherSuiteName(resp.TLS.CipherSuite)

						if time.Now().After(cert.NotAfter) {
							sslInfo["Status"] = "Expired"
						} else {
							sslInfo["Status"] = "Valid"
						}
					}
				}

				// 2. Content Discovery (Fuzzing)
				// Only fuzz if the main port is responsive
				if err == nil {
					fmt.Fprintf(os.Stderr, "[%s:%d] Starting content discovery (%d paths)...\n", job.IP, job.Port, len(interestingPaths))
					for i, path := range interestingPaths {
						// Report progress every 10 paths
						if i > 0 && i%10 == 0 {
							remaining := len(interestingPaths) - i
							fmt.Fprintf(os.Stderr, "[%s:%d] Fuzzing Progress: %d tested, %d remaining (Total: %d)\n", job.IP, job.Port, i, remaining, len(interestingPaths))
						}
						// Ensure path starts with /
						if len(path) > 0 && path[0] != '/' {
							path = "/" + path
						}

						targetURL := baseURL + path
						resp, err := client.Get(targetURL)
						if err == nil {
							// Check for 200 OK and ensure it's not a false positive (like a custom 404 page returning 200)
							// For simplicity in this MVP, we trust 200 OK
							if resp.StatusCode == 200 {
								vulns = append(vulns, path)
							}
							resp.Body.Close()
						}
					}
				}
			}

			results <- Result{
				IP:              resolvedIP,
				Port:            job.Port,
				Open:            true,
				Banner:          banner,
				Headers:         headers,
				Vulnerabilities: vulns,
				SSLInfo:         sslInfo,
			}
			conn.Close()
		} else {
			results <- Result{IP: resolvedIP, Port: job.Port, Open: false}
		}
	}
}
