# A Self-Documenting Makefile: http://marmelab.com/blog/2016/02/29/auto-documented-makefile.html

# Project variables
PACKAGE = github.com/anchore/kubernetes-admission-controller

# Build variables
BUILD_DIR ?= build
BUILD_PACKAGE = ${PACKAGE}/cmd/kubernetes-admission-controller
COMMIT_HASH ?= $(shell git rev-parse --short HEAD 2>/dev/null)
BUILD_DATE ?= $(shell date +%FT%T%z)
# ldflags target the vars in cmd/kubernetes-admission-controller/version.go
# (main.version / main.gitCommit / main.buildDate). NOTE: the var is gitCommit,
# not commitHash.
LDFLAGS += -X main.version=$(VERSION) -X main.gitCommit=$(COMMIT_HASH) -X main.buildDate=$(BUILD_DATE)
export CGO_ENABLED ?= 0
ifeq (${VERBOSE}, 1)
	GOARGS += -v
endif

OPENAPI_GENERATOR_VERSION = v4.1.3
GOLANG_VERSION = $(shell awk '/^go /{print $$2; exit}' go.mod)

# goreleaser replaces Ko for building + publishing the release images and the
# GitHub Release. Pinned; installed into TEMPDIR by the release target.
TEMPDIR = ./.tmp
DISTDIR = ./dist
GORELEASER_VERSION = v2.12.3

ifeq "$(strip $(VERSION))" ""
 override VERSION = $(shell git describe --always --tags --dirty)
endif

.PHONY: bootstrap-go
bootstrap-go:
	go mod download

.PHONY: clean
clean: ## Clean the working area and the project
	rm -rf bin/ ${BUILD_DIR}/ $(DISTDIR) $(TEMPDIR)/goreleaser.yaml

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
build: bootstrap-go ## Compile the binary locally (no image, no publish)
	go build ${GOARGS} -ldflags "${LDFLAGS}" -o ${BUILD_DIR}/anchore-kubernetes-admission-controller ./cmd/kubernetes-admission-controller

.PHONY: install-goreleaser
install-goreleaser:
	@mkdir -p $(TEMPDIR)
	[ -f "$(TEMPDIR)/goreleaser" ] || GOBIN=$(abspath $(TEMPDIR)) go install github.com/goreleaser/goreleaser/v2@$(GORELEASER_VERSION)

.PHONY: release
release: bootstrap-go install-goreleaser ## Build + publish the release images, binaries, and GitHub Release
	# create a config with the dist dir overridden (mirrors the other integrations)
	echo "dist: $(DISTDIR)" > $(TEMPDIR)/goreleaser.yaml
	cat .goreleaser.yaml >> $(TEMPDIR)/goreleaser.yaml
	$(TEMPDIR)/goreleaser --clean --config $(TEMPDIR)/goreleaser.yaml

.PHONY: snapshot
snapshot: bootstrap-go install-goreleaser ## Local dry-run: build images + binaries WITHOUT publishing (for parity checks)
	echo "dist: $(DISTDIR)" > $(TEMPDIR)/goreleaser.yaml
	cat .goreleaser.yaml >> $(TEMPDIR)/goreleaser.yaml
	$(TEMPDIR)/goreleaser release --skip=publish --clean --snapshot --config $(TEMPDIR)/goreleaser.yaml

.PHONY: test
test: bootstrap-go
	go test -v ./...
