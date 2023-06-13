# A Self-Documenting Makefile: http://marmelab.com/blog/2016/02/29/auto-documented-makefile.html

# Project variables
PACKAGE = github.com/anchore/kubernetes-admission-controller
DOCKER_RELEASE_REPO ?= docker.io/anchore/kubernetes-admission-controller

# Build variables
BUILD_DIR ?= build
BUILD_PACKAGE = ${PACKAGE}/cmd
#VERSION ?= $(shell git rev-parse --abbrev-ref HEAD)
COMMIT_HASH ?= $(shell git rev-parse --short HEAD 2>/dev/null)
BUILD_DATE ?= $(shell date +%FT%T%z)
LDFLAGS += -X main.version=$(VERSION) -X main.commitHash=$(COMMIT_HASH) -X main.buildDate=$(BUILD_DATE)
export CGO_ENABLED ?= 0
ifeq (${VERBOSE}, 1)
	GOARGS += -v
endif

## Build variables
IMAGE_LABELS := --image-label "org.opencontainers.image.created=$(BUILD_DATE)" \
	--image-label "org.opencontainers.image.title=anchore-kubernetes-admission-controller" \
	--image-label 'org.opencontainers.image.description=K8s Admission Controller using Anchore to validate images prior to admission' \
    --image-label "org.opencontainers.image.vendor=Anchore Inc." \
    --image-label 'org.opencontainers.image.licenses=Apache v2.0' \
    --image-label "org.opencontainers.image.version=$(VERSION)" \
    --image-label "org.opencontainers.image.source=${VCS_URL}" \
    --image-label "org.opencontainers.image.revision=$(COMMIT_HASH)" \


# Docker variables
DOCKER_TAG ?= $(VERSION)

ANCHORE_VERSION = 156836d
OPENAPI_GENERATOR_VERSION = v4.1.3
GOLANG_VERSION = 1.19

ifeq "$(strip $(VERSION))" ""
 override VERSION = $(shell git describe --always --tags --dirty)
endif

.PHONY: clean
clean: ## Clean the working area and the project
	rm -rf bin/ ${BUILD_DIR}/

.PHONY: build-binary
build-binary: goversion ## Build all binaries
ifeq (${VERBOSE}, 1)
	go env
endif
	@mkdir -p ${BUILD_DIR}
	go build ${GOARGS} -tags "${GOTAGS}" -ldflags "${LDFLAGS}" -o ${BUILD_DIR}/ ./cmd/...


.PHONY: goversion
goversion:
ifneq (${IGNORE_GOLANG_VERSION_REQ}, 1)
	@printf "${GOLANG_VERSION}\n$$(go version | awk '{sub(/^go/, "", $$3);print $$3}')" | sort -t '.' -k 1,1 -k 2,2 -k 3,3 -g | head -1 | grep -q -E "^${GOLANG_VERSION}$$" || (printf "Required Go version is ${GOLANG_VERSION}\nInstalled: `go version`" && exit 1)
endif

.PHONY: help
.DEFAULT_GOAL := help
help:
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build:
	COMMIT_HASH=$(COMMIT_HASH) VERSION=$(VERSION) BUILD_DATE=$(BUILD_DATE) KO_DOCKER_REPO=ko.local ko build ./cmd/kubernetes-admission-controller $(IMAGE_LABELS)

.PHONY: release
release:
	COMMIT_HASH=$(COMMIT_HASH) VERSION=$(VERSION) BUILD_DATE=$(BUILD_DATE) KO_DOCKER_REPO=$(DOCKER_RELEASE_REPO) ko build --tags $(DOCKER_TAG) --bare ./cmd/kubernetes-admission-controller $(IMAGE_LABELS)

.PHONY: test
test:
	go test -v ./...
