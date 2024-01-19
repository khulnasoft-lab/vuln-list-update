package alpineunfixed

import (
	"context"
	"encoding/json"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/khulnasoft-lab/vuln-list-update/utils"
	"golang.org/x/xerrors"
)

const (
	alpineDir         = "alpine-unfixed"
	secFixURL         = "https://khulnasoft-lab.github.io/secfixes-tracker/all.tar.gz"
	defaultPermission = 0755
)

type Updater struct {
	*options
}

type options struct {
	vulnListDir string
	url         string
}

type option func(*options)

func WithVulnListDir(dir string) option {
	return func(opts *options) {
		opts.vulnListDir = dir
	}
}

func WithURL(url string) option {
	return func(opts *options) {
		opts.url = url
	}
}

func NewUpdater(opts ...option) Updater {
	o := &options{
		vulnListDir: utils.VulnListDir(),
		url:         secFixURL,
	}

	for _, opt := range opts {
		opt(o)
	}
	return Updater{
		options: o,
	}
}

func (u Updater) Update() error {
	dir := filepath.Join(u.vulnListDir, alpineDir)
	log.Printf("Removing Alpine directory %s", dir)
	if err := os.RemoveAll(dir); err != nil {
		return xerrors.Errorf("failed to remove Alpine unfixed directory: %w", err)
	}

	if err := os.MkdirAll(dir, defaultPermission); err != nil {
		return xerrors.Errorf("mkdir error: %w", err)
	}

	log.Println("Fetching Alpine unfixed data...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	tmpDir, err := utils.DownloadToTempDir(ctx, u.url)
	if err != nil {
		return xerrors.Errorf("Alpine secfixes download error: %w", err)
	}
	defer func() {
		if rErr := os.RemoveAll(tmpDir); rErr != nil {
			log.Printf("Error removing temp directory: %v", rErr)
		}
	}()

	log.Println("Saving Alpine unfixed data...")
	err = filepath.Walk(tmpDir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		} else if info.IsDir() {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return xerrors.Errorf("file open error: %w", err)
		}
		defer f.Close()

		var vuln unfixedVulnerability
		if err = json.NewDecoder(f).Decode(&vuln); err != nil {
			return xerrors.Errorf("JSON decode error: %w", err)
		}

		filePath := filepath.Join(dir, vuln.ID) + ".json"
		if err = utils.Write(filePath, vuln); err != nil {
			return xerrors.Errorf("write error: %w", err)
		}

		return nil
	})
	if err != nil {
		return xerrors.Errorf("walk error: %w", err)
	}

	return nil
}
