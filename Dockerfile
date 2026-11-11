# Binaries are built by GoReleaser, see .goreleaser.yaml.
FROM gcr.io/distroless/static:nonroot

ARG TARGETPLATFORM

# Both programs ship in one image so the scanner always matches the operator.
COPY $TARGETPLATFORM/sbom-operator $TARGETPLATFORM/sbom-scanner /usr/local/bin/

USER 65532:65532

CMD [ "sbom-operator" ]
