package main

import (
	"os"

	"github.com/alecthomas/kingpin/v2"

	"github.com/skpr/sbom-operator/cmd"
)

func main() {
	app := kingpin.New("sbom", "Generates SBOMs for container images running in Kubernetes")

	cmd.Operator(app)
	cmd.Scan(app)

	kingpin.MustParse(app.Parse(os.Args[1:]))
}
