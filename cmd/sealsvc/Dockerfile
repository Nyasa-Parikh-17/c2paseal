# syntax=docker/dockerfile:1
#
# sealsvc container image. Build from the repository root:
#
#   docker build -f cmd/sealsvc/Dockerfile -t sealsvc .
#
# A static CGO_ENABLED=0 binary on distroless/static, running as a
# non-root user. Configuration comes from flags or SEALSVC_* environment
# variables (see `sealsvc -h` and deploy/sealsvc/compose.yaml).

FROM --platform=$BUILDPLATFORM golang:1.27 AS build
ARG TARGETOS TARGETARCH
ARG VERSION=devel
WORKDIR /src
# Module files first, so dependency downloads are cached between builds.
COPY go.mod go.sum ./
COPY keys/awskms/go.mod keys/awskms/go.sum keys/awskms/
COPY keys/gcpkms/go.mod keys/gcpkms/go.sum keys/gcpkms/
COPY cmd/sealsvc/go.mod cmd/sealsvc/go.sum cmd/sealsvc/
RUN cd cmd/sealsvc && go mod download
COPY . .
RUN cd cmd/sealsvc && \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -buildvcs=false -ldflags="-s -w -X main.version=${VERSION}" -o /out/sealsvc .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/sealsvc /sealsvc
USER nonroot:nonroot
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD ["/sealsvc", "healthcheck"]
ENTRYPOINT ["/sealsvc"]
