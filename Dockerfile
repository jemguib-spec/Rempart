# Rempart DNS — multi-stage build (Docker ou Podman).
# Installation guidée : scripts/install.sh (Linux, macOS) ou scripts/install.ps1 (Windows).
#   podman build -t rempart .                  → production image (distroless, non-root)
#   (la cible prod est la dernière étape : c'est elle qu'un build sans --target produit)
#   podman build -t rempart:softhsm --target softhsm .  → demo image with SoftHSM2

FROM docker.io/library/golang:1.24-bookworm AS build
WORKDIR /src
COPY . .
ARG VERSION=1.1.0
# cgo is required to load PKCS#11 vendor libraries. Dependencies are vendored:
# the build needs no network access (air-gapped build farms).
RUN CGO_ENABLED=1 go build -mod=vendor -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" -o /out/rempart ./cmd/rempart \
 && mkdir -p /out/data && mkdir -p -m 0700 /out/run/secrets && /out/rempart version

# ---- SoftHSM demo / test image (software HSM, NOT for production keys) ----
FROM docker.io/library/debian:12-slim AS softhsm
RUN apt-get update && apt-get install -y --no-install-recommends softhsm2 opensc ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -r -u 65532 -d /var/lib/rempart rempart \
 && mkdir -p /var/lib/rempart /var/lib/softhsm/tokens && chown -R rempart /var/lib/rempart /var/lib/softhsm \
 && install -d -m 0700 -o rempart -g rempart /run/secrets
COPY --from=build /out/rempart /usr/local/bin/rempart
COPY deploy/softhsm/softhsm2.conf /etc/softhsm/softhsm2.conf
COPY deploy/softhsm/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY deploy/rempart.hsm.yaml /etc/rempart/rempart.yaml
USER rempart
EXPOSE 53/udp 53/tcp 853/tcp 853/udp 443/tcp 8080/tcp
VOLUME ["/var/lib/rempart", "/var/lib/softhsm/tokens", "/run/secrets"]
HEALTHCHECK --interval=30s --timeout=3s CMD ["/usr/local/bin/rempart", "healthcheck", "127.0.0.1:53"]
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# ---- production image ----
FROM gcr.io/distroless/cc-debian12:nonroot AS prod
COPY --from=build /out/rempart /usr/local/bin/rempart
COPY --from=build --chown=65532:65532 /out/data /var/lib/rempart
# Point de montage du volume de secrets : un volume neuf en reprend le
# propriétaire (copie de l'image à la première utilisation) ; setup-secrets le
# restreint ensuite en 0700.
COPY --from=build --chown=65532:65532 /out/run/secrets /run/secrets
COPY deploy/rempart.docker.yaml /etc/rempart/rempart.yaml
USER 65532:65532
EXPOSE 53/udp 53/tcp 853/tcp 853/udp 443/tcp 8080/tcp
VOLUME ["/var/lib/rempart", "/run/secrets"]
HEALTHCHECK --interval=30s --timeout=3s CMD ["/usr/local/bin/rempart", "healthcheck", "127.0.0.1:53"]
ENTRYPOINT ["/usr/local/bin/rempart"]
CMD ["-config", "/etc/rempart/rempart.yaml"]
