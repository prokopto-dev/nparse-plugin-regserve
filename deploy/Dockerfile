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

# The data directory, created here because the final image has no shell to create it in.
#
# A new Docker named volume is root-owned, and this image runs as uid 65532: without this the very
# first boot cannot create /data/regserve.db, the server comes up with no catalogue, and the deploy
# fails its readiness check AFTER the container swap. Docker initialises an empty volume from the
# image's directory at the mount point — contents, ownership and mode — so shipping /data owned by
# 65532 is what makes the volume writable. Verified against both a brand-new volume and one that
# already existed empty, which is the state on the droplet today.
RUN mkdir -p /out/data && chown 65532:65532 /out/data

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

# The mount point, owned by the uid below. See the RUN in the build stage for why it exists at all.
# --chown takes numeric ids because scratch has no /etc/passwd for a name to resolve against.
COPY --from=build --chown=65532:65532 /out/data /data

# Non-root by number: scratch has no /etc/passwd, so a name would not resolve. 65532 is the
# conventional "nonroot" uid.
USER 65532:65532

# Read by `serve` and by `migrate`. The volume must be writable by uid 65532: SQLite creates its WAL
# and shared-memory files beside the database, so the directory matters as much as the file.
ENV REGSERVE_DB_PATH=/data/regserve.db
VOLUME ["/data"]
EXPOSE 8080

# No shell and no curl in this image, so the binary probes itself. Liveness only: it deliberately
# does not touch the database, because a brief disk problem should not restart-loop a container
# that would recover.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/regserve", "healthcheck", "--addr", ":8080"]

ENTRYPOINT ["/usr/local/bin/regserve"]

# No --seed here: where the seed comes from is a deployment decision, not an image one, and baking a
# path in would make every `docker run` fail on a file it has no reason to have. Set
# REGSERVE_SEED_PATH, or override the command — deploy/compose.yaml does the latter. Without one the
# server starts against REGSERVE_DB_PATH and serves whatever the database holds, which on a fresh
# volume is an empty catalogue: the boot log says so, loudly.
CMD ["serve", "--addr", ":8080"]
