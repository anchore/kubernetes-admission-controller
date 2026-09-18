# Consumed by goreleaser (`dockers:` in .goreleaser.yaml): it copies the
# already-built binary into a minimal image. This is NOT a from-source build —
# goreleaser compiles the binary, then this Dockerfile just packages it, matching
# the minimal/distroless base the previous Ko release produced.
FROM gcr.io/distroless/static-debian11:debug@sha256:a0a404776dec98be120089ae42bbdfbe48c177921d856937d124d48eb8c0b951 AS build

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

WORKDIR /tmp

# Keep the binary at the same path Ko published it to (/ko-app/...): the helm
# chart's deployment hardcodes `command: [/ko-app/kubernetes-admission-controller]`,
# so this makes the goreleaser image a drop-in replacement with no chart change.
COPY anchore-kubernetes-admission-controller /ko-app/kubernetes-admission-controller

ARG BUILD_DATE
ARG BUILD_VERSION
ARG VCS_REF
ARG VCS_URL

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.title="anchore-kubernetes-admission-controller"
LABEL org.opencontainers.image.description="K8s Admission Controller using Anchore to validate images prior to admission"
LABEL org.opencontainers.image.source=$VCS_URL
LABEL org.opencontainers.image.revision=$VCS_REF
LABEL org.opencontainers.image.vendor="Anchore, Inc."
LABEL org.opencontainers.image.version=$BUILD_VERSION
LABEL org.opencontainers.image.licenses="Apache-2.0"

USER 1000

ENTRYPOINT ["/ko-app/kubernetes-admission-controller"]
