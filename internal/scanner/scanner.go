// Package scanner generates a CycloneDX SBOM from a filesystem, eg. a mounted container image.
package scanner

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	scalibr "github.com/google/osv-scalibr"
	"github.com/google/osv-scalibr/converter"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/plugin"
	pl "github.com/google/osv-scalibr/plugin/list"
)

// DefaultPlugins used to discover packages.
var DefaultPlugins = []string{"os", "php", "javascript", "python", "go", "java", "ruby", "rust", "dotnet"}

// Generate scans the filesystem and converts the discovered packages into a CycloneDX document.
func Generate(ctx context.Context, path, name string, names []string) (*cyclonedx.BOM, error) {
	plugins, err := pl.FromNames(names, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to load plugins: %w", err)
	}

	// The filesystem is a mounted image, not the system we are running on.
	capabilities := &plugin.Capabilities{
		OS:       plugin.OSLinux,
		Network:  plugin.NetworkOffline,
		DirectFS: true,
	}

	result := scalibr.New().Scan(ctx, &scalibr.ScanConfig{
		Plugins:      plugin.FilterByCapabilities(plugins, capabilities),
		Capabilities: capabilities,
		ScanRoots:    scalibrfs.RealFSScanRoots(path),
	})

	if result.Status != nil && result.Status.Status == plugin.ScanStatusFailed {
		return nil, fmt.Errorf("scan failed: %s", result.Status.FailureReason)
	}

	return converter.ToCDX(result.Inventory, converter.CDXConfig{
		ComponentName: name,
		ComponentType: string(cyclonedx.ComponentTypeContainer),
	}), nil
}

// Encode the CycloneDX document as gzipped JSON.
func Encode(bom *cyclonedx.BOM) ([]byte, error) {
	var buf bytes.Buffer

	writer := gzip.NewWriter(&buf)

	if err := cyclonedx.NewBOMEncoder(writer, cyclonedx.BOMFileFormatJSON).EncodeVersion(bom, cyclonedx.SpecVersion1_6); err != nil {
		return nil, err
	}

	if err := writer.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
