FROM golang:1.24-alpine AS builder

RUN mkdir -p /build
WORKDIR /build
COPY go.* /build/
RUN go mod download
COPY . /build
RUN CGO_ENABLED=0 GOOS=linux go build -a -o /anchore-kubernetes-admission-controller ./cmd/kubernetes-admission-controller/

FROM registry.access.redhat.com/ubi8/ubi-minimal:latest

COPY --from=builder /anchore-kubernetes-admission-controller /anchore-kubernetes-admission-controller
CMD ["/anchore-kubernetes-admission-controller"]
