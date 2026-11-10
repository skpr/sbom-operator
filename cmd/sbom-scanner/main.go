// Package main generates an SBOM for a mounted image and stores it in S3. It is run by the operator in scanner Pods.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/alecthomas/kingpin/v2"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/skpr/sbom-operator/internal/controller/sbom"
	"github.com/skpr/sbom-operator/internal/scanner"
)

type scanCommand struct {
	Path           string
	Name           string
	Plugins        []string
	Bucket         string
	Key            string
	Endpoint       string
	TerminationLog string
}

func (c *scanCommand) run(_ *kingpin.ParseContext) error {
	ctx := context.Background()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	logger.Info("Generating SBOM", "path", c.Path, "name", c.Name)

	bom, err := scanner.Generate(ctx, c.Path, c.Name, c.Plugins)
	if err != nil {
		return fmt.Errorf("failed to generate: %w", err)
	}

	packages := len(*bom.Components)

	logger.Info("Encoding SBOM", "packages", packages)

	data, err := scanner.Encode(bom)
	if err != nil {
		return fmt.Errorf("failed to encode: %w", err)
	}

	logger.Info("Uploading SBOM", "bucket", c.Bucket, "key", c.Key, "bytes", len(data))

	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		if c.Endpoint != "" {
			o.BaseEndpoint = aws.String(c.Endpoint)
			o.UsePathStyle = true
		}
	})

	_, err = client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(c.Bucket),
		Key:         aws.String(c.Key),
		Body:        bytes.NewReader(data),
		ContentType: aws.String("application/gzip"),
	})
	if err != nil {
		return fmt.Errorf("failed to upload: %w", err)
	}

	message, err := json.Marshal(sbom.TerminationMessage{
		Packages: packages,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal termination message: %w", err)
	}

	if err := os.WriteFile(c.TerminationLog, message, 0644); err != nil {
		return fmt.Errorf("failed to write termination message: %w", err)
	}

	logger.Info("SBOM generation complete")

	return nil
}

func main() {
	c := new(scanCommand)

	cmd := kingpin.New("sbom-scanner", "Generates an SBOM for a filesystem and stores it in S3").Action(c.run)

	cmd.Flag("path", "Path to the filesystem which will be scanned").Envar("SBOM_PATH").Default("/scan").StringVar(&c.Path)
	cmd.Flag("name", "Name of the component being scanned eg. the image reference").Envar("SBOM_NAME").Required().StringVar(&c.Name)
	cmd.Flag("plugin", "Extractors used to discover packages").Envar("SBOM_PLUGINS").Default(scanner.DefaultPlugins...).StringsVar(&c.Plugins)
	cmd.Flag("bucket", "S3 bucket where the SBOM will be stored").Envar("SBOM_BUCKET").Required().StringVar(&c.Bucket)
	cmd.Flag("key", "Key where the SBOM will be stored").Envar("SBOM_KEY").Required().StringVar(&c.Key)
	cmd.Flag("endpoint", "Endpoint override for S3 compatible storage").Envar("SBOM_ENDPOINT").StringVar(&c.Endpoint)
	cmd.Flag("termination-log", "Path where the result summary will be written").Envar("SBOM_TERMINATION_LOG").Default("/dev/termination-log").StringVar(&c.TerminationLog)

	kingpin.MustParse(cmd.Parse(os.Args[1:]))
}
