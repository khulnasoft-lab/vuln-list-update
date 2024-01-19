package k8s

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/khulnasoft-lab/vuln-list-update/osv"
	"github.com/khulnasoft-lab/vuln-list-update/utils"
	uu "github.com/khulnasoft-lab/vuln-list-update/utils"
	"golang.org/x/xerrors"
)

const (
	K8sVulnDBURL    = "https://kubernetes.io/docs/reference/issues-security/official-cve-feed/index.json"
	MitreURL        = "https://cveawg.mitre.org/api/cve"
	CVEList         = "https://www.cve.org/"
	UpstreamFolder  = "upstream"
	TimeoutDuration = 5 * time.Second
)

// ... (unchanged code)

type options struct {
	mitreURL string
}

// ... (unchanged code)

type Updater struct {
	*options
}

// ... (unchanged code)

func NewUpdater(opts ...option) Updater {
	o := &options{
		mitreURL: MitreURL,
	}
	for _, opt := range opts {
		opt(o)
	}
	return Updater{
		options: o,
	}
}

// ... (unchanged code)

func (u Updater) Collect() (*VulnDB, error) {
	// ... (unchanged code)
}

// ... (unchanged code)

const (
	// ExcludeNonCoreComponentsCves exclude CVEs with missing data or non-K8s core components
	ExcludeNonCoreComponentsCves = "CVE-2019-11255,CVE-2020-10749,CVE-2020-8554"
)

// ... (unchanged code)

func (u Updater) Update() error {
	if err := u.update(); err != nil {
		return xerrors.Errorf("error in k8s update: %w", err)
	}
	return nil
}

// ... (unchanged code)

func (u Updater) update() error {
	// ... (unchanged code)
}

// ... (unchanged code)
