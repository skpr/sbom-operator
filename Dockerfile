# Build on the native platform and cross compile, instead of emulating each target platform.
FROM --platform=$BUILDPLATFORM golang:1.26 AS build

ARG TARGETOS TARGETARCH

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/ ./cmd/...

FROM gcr.io/distroless/static:nonroot

# Both programs ship in one image so the scanner always matches the operator.
COPY --from=build /out/ /usr/local/bin/

USER 65532:65532

CMD [ "sbom-operator" ]
