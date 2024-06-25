package mariner_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/khulnasoft-lab/vuln-list-update/mariner"
)

func TestUpdate(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		wantErr   string
	}{
		{
			name:      "happy path",
			inputFile: "file::testdata/happy",
		},
		{
			name:      "sad path, invalid xml",
			inputFile: "file::testdata/sad",
			wantErr:   "failed to decode xml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			cc := mariner.NewConfig(mariner.WithURL(tt.inputFile), mariner.WithDir(tmpDir), mariner.WithRetry(0))

			err := cc.Update()
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)

			err = filepath.WalkDir(tmpDir, func(path string, d fs.DirEntry, err error) error {
				require.NoError(t, err, tt.name)
				if !d.Type().IsRegular() {
					return nil
				}

				got, err := os.ReadFile(path)
				require.NoError(t, err, path)

				rel, err := filepath.Rel(tmpDir, path)
				require.NoError(t, err, path)

				goldenPath := filepath.Join("testdata", "golden", "mariner", rel)
				want, err := os.ReadFile(goldenPath)
				require.NoError(t, err, goldenPath)

				assert.JSONEq(t, string(want), string(got), path)

				return nil
			})
			require.NoError(t, err, tt.name)
		})
	}
}

// AdvisoryID returns advisoryID for Definition.
// If `advisory_id` field does not exist, create this field yourself using the Azure Linux format.
//
// Azure Linux uses `<number_after_last_colon_from_id>-<last_number_from_version>` format for `advisory_id`.
// cf. https://github.com/khulnasoft-lab/vuln-list-update/pull/271#issuecomment-2111678641
// e.g.
//   - `id="oval:com.microsoft.cbl-mariner:def:27423" version="2000000001"` => `27423-1`
//   - `id="oval:com.microsoft.cbl-mariner:def:11073" version="2000000000"` => `11073`
//   - `id="oval:com.microsoft.cbl-mariner:def:6343" version="1"` => `6343-1`
//   - `id="oval:com.microsoft.cbl-mariner:def:6356" version="0"` => `6356`
func AdvisoryID(def Definition) string {
	id := def.Metadata.AdvisoryID
	if id == "" {
		ss := strings.Split(def.ID, ":")
		id = ss[len(ss)-1]
		// for `0` versions `-0` suffix is omitted.
		if def.Version != "" && def.Version[len(def.Version)-1:] != "0" {
			id = fmt.Sprintf("%s-%s", id, def.Version[len(def.Version)-1:])
		}
	}
}
