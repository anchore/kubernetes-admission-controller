FROM golang:1-alpine

WORKDIR /go/src/github.com/anchore/kubernetes-admission-controller
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -o /anchore-kubernetes-admission-controller ./cmd/kubernetes-admission-controller/
CMD ["/anchore-kubernetes-admission-controller"]
