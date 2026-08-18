# syntax=docker/dockerfile:1
#
# Two stages, final image FROM scratch.
#
# CGO is off (modernc.org/sqlite is pure Go), so there is nothing to link against and the image can
# be empty apart from the binary, the CA bundle and the tzdata it needs. An empty image is not
# austerity: it is the difference between "a CVE in the base image" being a rebuild and being an
# incident, and this service holds every publisher's credentials.

FROM --platform=$BUILDPLATFORM golang:1.26-bookworm@sha256:116d58cbd88c1297624acc6e967a060012422bacf9930927e23fb719189c6f36 AS build

WORKDIR /src

# Dependencies first, so a source-only change does not re-download the module graph.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown

# Cross-compile rather than emulate: buildx with QEMU is minutes per architecture, and Go does this
# natively in seconds. CGO_ENABLED=0 is what makes FROM scratch possible at all.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath \
      -ldflags="-s -w \
        -X main.version=${VERSION} \
        -X main.commit=${COMMIT} \
        -X main.buildDate=${BUILD_DATE}" \
      -o /out/regserve ./cmd/regserve

FROM scratch

# The artifact fetcher and the GitHub OAuth provider speak TLS to the public internet, so the CA
# bundle is not optional. zoneinfo is here because the binary formats timestamps and a scratch image
# has no tzdata — without it every local-time rendering silently becomes UTC.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=build /out/regserve /usr/local/bin/regserve

# Non-root by number: scratch has no /etc/passwd, so a name would not resolve. 65532 is the
# conventional "nonroot" uid. The data volume must be writable by it — see deploy/compose.yaml.
USER 65532:65532

ENV REGSERVE_DB_PATH=/data/regserve.db
VOLUME ["/data"]
EXPOSE 8080

# No shell and no curl in this image, so the binary probes itself. Liveness only: it deliberately
# does not touch the database, because a brief disk problem should not restart-loop a container
# that would recover.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/regserve", "healthcheck", "--addr", ":8080"]

ENTRYPOINT ["/usr/local/bin/regserve"]
CMD ["serve", "--addr", ":8080"]
