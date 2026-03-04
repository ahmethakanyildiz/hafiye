package util

import (
	"fmt"
	"hafiye/gutil"
	"os"
	"runtime"
	"sync"
)

// WORKER/RUN FUNCTIONS
func RunScan(
	scanRoot string,
	paths []string,
	workers int,
	findings *[]Finding,
	scanFile func(absPath string, displayPath string, results chan<- Finding) error,
) error {
	if len(paths) == 0 {
		return nil
	}
	if findings == nil {
		return fmt.Errorf("findings pointer is nil")
	}

	scanRootAbs, rootBase, err := gutil.GetScanRootAbsAndRootBase(scanRoot)
	if err != nil {
		return err
	}

	workers = getWorkerCount(workers, paths)

	jobs := make(chan string, workers)
	results := make(chan Finding, 256*workers)

	var aggWG sync.WaitGroup
	aggWG.Add(1)
	go func() {
		defer aggWG.Done()
		for f := range results {
			*findings = append(*findings, f)
		}
	}()

	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for p := range jobs {
				displayPath := gutil.MakeDisplayPath(scanRootAbs, rootBase, p)
				absPath := gutil.NormalizePath(p)

				if err := scanFile(absPath, displayPath, results); err != nil {
					fmt.Fprintf(os.Stderr, "WARNING: cannot scan file: %s (%v)\n", absPath, err)
					continue
				}
			}
		}()
	}

	for _, p := range paths {
		jobs <- p
	}
	close(jobs)

	wg.Wait()
	close(results)
	aggWG.Wait()

	return nil
}

func getWorkerCount(workers int, paths []string) int {
	if workers <= 0 {
		workers = 5
	}

	if workers > len(paths) {
		workers = len(paths)
	}

	if workers > runtime.NumCPU()*4 {
		workers = runtime.NumCPU() * 4
	}
	if workers < 1 {
		workers = 1
	}

	return workers
}
