package engine

import (
	"context"
	"skyscan/pkg/core"
	"sync"
)

type Runner struct {
	providers []core.Provider
	config    *core.Config
	results   chan *core.Result
}

func NewRunner(config *core.Config, providers []core.Provider) *Runner {
	return &Runner{
		providers: providers,
		config:    config,
		results:   make(chan *core.Result),
	}
}

func (r *Runner) Start(ctx context.Context, keyword string) <-chan *core.Result {
	// 1. Generator Channel
	jobs := make(chan struct {
		Provider core.Provider
		Target   string
	}, 10000)

	// 2. Dispatcher (Generator)
	var wgGen sync.WaitGroup
	for _, p := range r.providers {
		wgGen.Add(1)
		go func(prov core.Provider) {
			defer wgGen.Done()
			// Create a pipe for this provider
			pChan := make(chan string)
			go func() {
				defer close(pChan)
				prov.Generate(ctx, keyword, pChan)
			}()

			for target := range pChan {
				select {
				case <-ctx.Done():
					return
				case jobs <- struct {
					Provider core.Provider
					Target   string
				}{Provider: prov, Target: target}:
				}
			}
		}(p)
	}

	// Close jobs when all generators are done
	go func() {
		wgGen.Wait()
		close(jobs)
	}()

	// 3. Worker Pool
	var wgWorkers sync.WaitGroup
	for i := 0; i < r.config.Threads; i++ {
		wgWorkers.Add(1)
		go func() {
			defer wgWorkers.Done()
			for job := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					res, err := job.Provider.Check(ctx, job.Target)
					if err == nil && res != nil {
						r.results <- res
					}
				}
			}
		}()
	}

	// Close results when all workers are done
	go func() {
		wgWorkers.Wait()
		close(r.results)
	}()

	return r.results
}
