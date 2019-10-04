FROM golang:1.13-alpine AS builder

RUN apk add --update --no-cache ca-certificates git
RUN mkdir -p /build
WORKDIR /build
COPY go.* /build/
RUN go mod download
COPY . /build
RUN CGO_ENABLED=0 GOOS=linux go build -a -o /anchore-kubernetes-admission-controller ./cmd/kubernetes-admission-controller/

FROM alpine:3.10

COPY --from=builder /anchore-kubernetes-admission-controller /anchore-kubernetes-admission-controller
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
CMD ["/anchore-kubernetes-admission-controller"]