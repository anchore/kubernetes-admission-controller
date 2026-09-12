FROM golang:1.26-alpine AS builder

# The base tag is only a bootstrap: GOTOOLCHAIN=auto lets the go directive in go.mod
# upgrade the toolchain, so go.mod stays the one place the Go version is bumped. The
# golang images default to GOTOOLCHAIN=local, which would silently compile with the
# base image's Go instead. Note this only ever upgrades -- keep the tag on the minor
# that go.mod targets so the patch matches what CI builds.
ENV GOTOOLCHAIN=auto

RUN mkdir -p /build
WORKDIR /build
COPY go.* /build/
RUN go mod download
COPY . /build
RUN CGO_ENABLED=0 GOOS=linux go build -a -o /anchore-kubernetes-admission-controller ./cmd/kubernetes-admission-controller/

FROM registry.access.redhat.com/ubi8/ubi-minimal:latest

COPY --from=builder /anchore-kubernetes-admission-controller /anchore-kubernetes-admission-controller
CMD ["/anchore-kubernetes-admission-controller"]
