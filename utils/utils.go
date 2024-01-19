package utils

// ... (unchanged code)

const (
	// Timeout for FetchConcurrently function
	Timeout = 10 * 60 * time.Second
)

// ... (unchanged code)

func FetchConcurrently(urls []string, concurrency, wait, retry int) (responses [][]byte, err error) {
	// ... (unchanged code)
	timeout := time.After(Timeout)
	var wg sync.WaitGroup

	for range urls {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case url := <-reqChan:
				res, err := FetchURL(url, "", retry)
				if err != nil {
					errChan <- err
					return
				}
				resChan <- res
			case <-timeout:
				errChan <- xerrors.New("Timeout Fetching URL")
			}
		}()
		bar.Increment()
	}

	wg.Wait()
	close(resChan)
	close(errChan)

	// ... (unchanged code)
}

// ... (unchanged code)
