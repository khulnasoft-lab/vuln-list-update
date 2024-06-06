# vuln-list-update

[![Go Report Card][report-card-img]][report-card]
[![License][license-img]][license]
[![Update vuln-list repo](https://github.com/khulnasoft-lab/vuln-list-update/actions/workflows/update.yml/badge.svg)](https://github.com/khulnasoft-lab/vuln-list-update/actions/workflows/update.yml)

[report-card-img]: https://goreportcard.com/badge/github.com/khulnasoft-lab/vuln-list-update
[report-card]: https://goreportcard.com/report/github.com/khulnasoft-lab/vuln-list-update
[license-img]: https://img.shields.io/badge/License-Apache%202.0-blue.svg
[license]: https://github.com/khulnasoft-lab/vuln-list-update/blob/main/LICENSE

Collect vulnerability information and save it in parsable format automatically

## Data
https://github.com/khulnasoft-lab/vuln-list/

## Usage

```
$ vuln-list-update -h
Usage of vuln-list-update:
  -target string
    	update target (nvd, alpine, alpine-unfixed, redhat, redhat-oval, debian, debian-oval, ubuntu, amazon, oracle-oval, suse-cvrf, photon, arch-linux, ghsa, glad, cwe, osv, go-vulndb, mariner, kevc, wolfi, chainguard)
  -target-branch string
    	alternative repository branch (only glad)
  -target-uri string
    	alternative repository URI (only glad)
  -years string
    	update years (only redhat)
```

## License

For [LICENSE](https://github.com/khulnasoft-lab/vuln-list-update/blob/main/LICENSE) file in this repository.
