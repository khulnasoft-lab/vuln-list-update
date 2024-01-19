package alpine

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"path"
	"path/filepath"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/khulnasoft-lab/vuln-list-update/utils"
	"github.com/spf13/afero"
	"golang.org/x/xerrors"
)

const (
	alpineDir = "alpine"
	repoURL   = "https://secdb.alpinelinux.org/"
	retry     = 3
)

type Updater struct {
	vulnListDir string
	advisoryDir string
	appFs       afero.Fs
	baseURL     *url.URL
	retry       int
}

type option func(*Updater)

func WithVulnListDir(v string) option {
	return func(u *Updater) { u.vulnListDir = v }
}

func WithAdvisoryDir(s string) option {
	return func(u *Updater) { u.advisoryDir = s }
}

func WithAppFs(v afero.Fs) option {
	return func(u *Updater) { u.appFs = v }
}

func WithBaseURL(v *url.URL) option {
	return func(u *Updater) { u.baseURL = v }
}

func WithRetry(v int) option {
	return func(u *Updater) { u.retry = v }
}

func NewUpdater(options ...option) *Updater {
	u, _ := url.Parse(repoURL)
	updater := &Updater{
		vulnListDir: utils.VulnListDir(),
		advisoryDir: alpineDir,
		appFs:       afero.NewOsFs(),
		baseURL:     u,
		retry:       retry,
	}
	for _, option := range options {
		option(updater)
	}

	return updater
}

func (u Updater) Update() (err error) {
	dir := filepath.Join(u.vulnListDir, u.advisoryDir)
	log.Printf("Remove Alpine directory %s", dir)
	if err := u.appFs.RemoveAll(dir); err != nil {
		return xerrors.Errorf("failed to remove Alpine directory: %w", err)
	}
	if err := u.appFs.MkdirAll(dir, 0755); err != nil {
		return err
	}

	log.Println("Fetching Alpine data...")
	b, err := utils.FetchURL(u.baseURL.String(), "", u.retry)
	if err != nil {
		return err
	}

	d, err := goquery.NewDocumentFromReader(bytes.NewReader(b))
	if err != nil {
		return err
	}

	var releases []string
	d.Find("a").Each(func(i int, selection *goquery.Selection) {
		release := selection.Text()
		if !strings.HasPrefix(release, "v") && !strings.HasPrefix(release, "edge") {
			return
		}
		releases = append(releases, release)
	})

	for _, release := range releases {
		releaseURL := *u.baseURL
		releaseURL.Path = path.Join(releaseURL.Path, release)
		files, err := u.traverse(releaseURL)
		if err != nil {
			return err
		}

		for _, file := range files {
			if err = u.saveReleaseFile(release, file); err != nil {
				return err
			}
		}
	}

	return nil
}

func (u Updater) traverse(url url.URL) ([]string, error) {
	b, err := utils.FetchURL(url.String(), "", u.retry)
	if err != nil {
		return nil, err
	}

	d, err := goquery.NewDocumentFromReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}

	var files []string
	d.Find("a").Each(func(i int, selection *goquery.Selection) {
		if strings.HasSuffix(selection.Text(), ".json") {
			files = append(files, selection.Text())
		}
	})
	return files, nil
}

func (u Updater) saveReleaseFile(release, fileName string) error {
	log.Printf("  release: %s, file: %s", release, fileName)
	advisoryURL := *u.baseURL
	advisoryURL.Path = path.Join(advisoryURL.Path, release, fileName)
	b, err := utils.FetchURL(advisoryURL.String(), "", u.retry)
	if err != nil {
		return err
	}

	var secdb secdb
	if err = json.Unmarshal(b, &secdb); err != nil {
		return err
	}

	packages, err := u.unmarshalPackages(secdb.Packages)
	if err != nil {
		return err
	}

	for _, pkg := range packages {
		if err = u.savePackage(secdb, pkg, release); err != nil {
			return err
		}
	}

	return nil
}

func (u Updater) unmarshalPackages(packagesJSON json.RawMessage) ([]packages, error) {
	var v interface{}
	if err := json.Unmarshal(packagesJSON, &v); err != nil {
		return nil, err
	}

	pkgs, ok := v.([]interface{})
	if !ok {
		log.Printf("    skip unmarshaling packages: %s", v)
		return nil, nil
	}

	var result []packages
	for _, pkg := range pkgs {
		pkgJSON, err := json.Marshal(pkg)
		if err != nil {
			log.Printf("    skip unmarshaling package: %s", pkg)
			continue
		}

		var p packages
		if err := json.Unmarshal(pkgJSON, &p); err != nil {
			log.Printf("    skip unmarshaling package JSON: %s", pkgJSON)
			continue
		}
		result = append(result, p)
	}

	return result, nil
}

func (u Updater) savePackage(secdb secdb, pkg packages, release string) error {
	secfixes := map[string][]string{}
	for fixedVersion, v := range pkg.Secfixes {
		cveIDs, err := u.unmarshalCVEs(v)
		if err != nil {
			log.Printf("    skip package: %s, version: %s", pkg.Name, fixedVersion)
			continue
		}
		secfixes[fixedVersion] = cveIDs
	}

	advisory := advisory{
		Name:          pkg.Name,
		Secfixes:      secfixes,
		Apkurl:        secdb.Apkurl,
		Archs:         secdb.Archs,
		Urlprefix:     secdb.Urlprefix,
		Reponame:      secdb.Reponame,
		Distroversion: secdb.Distroversion,
	}

	release = strings.TrimPrefix(release, "v")
	dir := filepath.Join(u.vulnListDir, u.advisoryDir, release, secdb.Reponame)
	file := fmt.Sprintf("%s.json", pkg.Name)
	if err := utils.WriteJSON(u.appFs, dir, file, advisory); err != nil {
		return xerrors.Errorf("failed to write %s under %s: %w", file, dir, err)
	}

	return nil
}

func (u Updater) unmarshalCVEs(v interface{}) ([]string, error) {
	cveIDs, ok := v.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected format for CVE IDs: %v", v)
	}

	var result []string
	for _, cveID := range cveIDs {
		if id, ok := cveID.(string); ok {
			result = append(result, id)
		} else {
			log.Printf("    skip unmarshaling CVE ID: %v", cveID)
		}
	}

	return result, nil
}
