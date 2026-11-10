package scanner

import (
	"bytes"
	"compress/gzip"
	"context"
	"testing"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
)

func TestGenerate(t *testing.T) {
	bom, err := Generate(context.TODO(), "testdata/rootfs", "example.com/app:0.0.1", []string{"os", "php"})
	assert.NoError(t, err)

	assert.Equal(t, "example.com/app:0.0.1", bom.Metadata.Component.Name)
	assert.Equal(t, cyclonedx.ComponentTypeContainer, bom.Metadata.Component.Type)

	var names []string
	for _, component := range *bom.Components {
		names = append(names, component.Name)
	}

	assert.ElementsMatch(t, []string{"musl", "busybox", "drupal/core"}, names)
}

func TestEncode(t *testing.T) {
	bom, err := Generate(context.TODO(), "testdata/rootfs", "example.com/app:0.0.1", []string{"php"})
	assert.NoError(t, err)

	data, err := Encode(bom)
	assert.NoError(t, err)

	reader, err := gzip.NewReader(bytes.NewReader(data))
	assert.NoError(t, err)

	decoded := new(cyclonedx.BOM)
	err = cyclonedx.NewBOMDecoder(reader, cyclonedx.BOMFileFormatJSON).Decode(decoded)
	assert.NoError(t, err)

	assert.Equal(t, cyclonedx.SpecVersion1_6, decoded.SpecVersion)
	assert.Len(t, *decoded.Components, 1)
	assert.Equal(t, "drupal/core", (*decoded.Components)[0].Name)
	assert.Equal(t, "10.3.1", (*decoded.Components)[0].Version)
	assert.Equal(t, "pkg:composer/drupal/core@10.3.1", (*decoded.Components)[0].PackageURL)
}
