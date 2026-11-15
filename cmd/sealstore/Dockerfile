# syntax=docker/dockerfile:1
#
# sealstore container image. Build from the repository root:
#
#   docker build -f cmd/sealstore/Dockerfile -t sealstore .
#   docker run -v ./store:/store sealstore serve --dir /store/data --api-keys /store/keys.txt
#
# A static CGO_ENABLED=0 binary on distroless/static, running as a non-root
# user. Mount a directory for the manifest stores and the API key file.

FROM --platform=$BUILDPLATFORM golang:1.27 AS build
ARG TARGETOS TARGETARCH
ARG VERSION=devel
WORKDIR /src
COPY go.mod go.sum ./
COPY watermark/go.mod watermark/go.sum watermark/
COPY cmd/sealstore/go.mod cmd/sealstore/go.sum cmd/sealstore/
RUN cd cmd/sealstore && go mod download
COPY . .
RUN cd cmd/sealstore && \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -buildvcs=false -ldflags="-s -w -X main.version=${VERSION}" -o /out/sealstore .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/sealstore /sealstore
USER nonroot:nonroot
EXPOSE 8090
ENTRYPOINT ["/sealstore"]
CMD ["serve", "--dir", "/store/data", "--api-keys", "/store/keys.txt"]
