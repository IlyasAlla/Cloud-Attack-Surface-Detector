package main

import (
    "encoding/json"
    "flag"
    "os"
    "sync"
    "strings"
    "strconv"
    "cloud-surface-detector/internal/worker"
)

// Input struct matches Python's TargetResource
type InputTarget struct {
    IP       string   `json:"ip_address"`
    Hostname string   `json:"hostname"`
    Paths    []string `json:"paths"`
}

func main() {
    concurrency := flag.Int("c", 1000, "Concurrency level")
    timeout := flag.Int("t", 2000, "Timeout in ms")
    portsFlag := flag.String("ports", "", "Comma-separated list of ports or ranges (e.g. 80,443,1000-2000)")
    flag.Parse()

    // 1. Stream Decode JSON from Stdin
    var targets []InputTarget
    decoder := json.NewDecoder(os.Stdin)
    if err := decoder.Decode(&targets); err != nil {
        // If empty input or error, just exit
        return
    }

    // 2. Setup Channels
    jobs := make(chan worker.Job, len(targets)*10) // buffer for multiple ports per IP
    results := make(chan worker.Result, len(targets)*10)
    var wg sync.WaitGroup

    // 3. Start Workers
    for i := 0; i < *concurrency; i++ {
        wg.Add(1)
        go worker.Worker(jobs, results, &wg, *timeout)
    }

    // 4. Dispatch Jobs
    var scanPorts []int
    if *portsFlag != "" {
        scanPorts = parsePorts(*portsFlag)
    } else {
        // Default top ports
        scanPorts = []int{22, 80, 443, 3389, 8080, 8443}
    }
    for _, t := range targets {
        for _, p := range scanPorts {
            jobs <- worker.Job{IP: t.IP, Hostname: t.Hostname, Port: p, Paths: t.Paths}
        }
    }
    close(jobs)

    // 5. Wait for completion
    wg.Wait()
    close(results)

    // 6. Aggregate and Output
    finalOutput := []worker.Result{}
    for r := range results {
        if r.Open {
            finalOutput = append(finalOutput, r)
        }
    }

    // : Marshal final results to JSON for Python
    encoder := json.NewEncoder(os.Stdout)
    encoder.Encode(finalOutput)
}

func parsePorts(portsStr string) []int {
    var ports []int
    parts := strings.Split(portsStr, ",")
    for _, part := range parts {
        part = strings.TrimSpace(part)
        if strings.Contains(part, "-") {
            rangeParts := strings.Split(part, "-")
            if len(rangeParts) == 2 {
                start, err1 := strconv.Atoi(rangeParts[0])
                end, err2 := strconv.Atoi(rangeParts[1])
                if err1 == nil && err2 == nil && start <= end {
                    for i := start; i <= end; i++ {
                        ports = append(ports, i)
                    }
                }
            }
        } else {
            if p, err := strconv.Atoi(part); err == nil {
                ports = append(ports, p)
            }
        }
    }
    return ports
}
