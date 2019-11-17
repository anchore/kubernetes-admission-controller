# A Self-Documenting Makefile: http://marmelab.com/blog/2016/02/29/auto-documented-makefile.html

# Project variables
PACKAGE = github.com/anchore/kubernetes-admission-controller
BINARY_NAME ?= kubernetes-admission-controller
DOCKER_IMAGE = anchore/kubernetes-admission-controller

# Build variables
BUILD_DIR ?= build
BUILD_PACKAGE = ${PACKAGE}/cmd
VERSION ?= $(shell git rev-parse --abbrev-ref HEAD)
COMMIT_HASH ?= $(shell git rev-parse --short HEAD 2>/dev/null)
BUILD_DATE ?= $(shell date +%FT%T%z)
LDFLAGS += -X main.version=${VERSION} -X main.commitHash=${COMMIT_HASH} -X main.buildDate=${BUILD_DATE}
export CGO_ENABLED ?= 0
ifeq (${VERBOSE}, 1)
	GOARGS += -v
endif

# Docker variables
DOCKER_TAG ?= ${VERSION}

ANCHORE_VERSION = 156836d
OPENAPI_GENERATOR_VERSION = v4.1.3
GOLANG_VERSION = 1.13

.PHONY: clean
clean: ## Clean the working area and the project
	rm -rf bin/ ${BUILD_DIR}/

.PHONY: build
build: goversion ## Build all binaries
ifeq (${VERBOSE}, 1)
	go env
endif

	@mkdir -p ${BUILD_DIR}
	go build ${GOARGS} -tags "${GOTAGS}" -ldflags "${LDFLAGS}" -o ${BUILD_DIR}/ ./cmd/...

.PHONY: build-release
build-release: ## Build all binaries without debug information
	@${MAKE} LDFLAGS="-w ${LDFLAGS}" GOARGS="${GOARGS} -trimpath" BUILD_DIR="${BUILD_DIR}/release" build

.PHONY: build-debug
build-debug: ## Build all binaries with remote debugging capabilities
	@${MAKE} GOARGS="${GOARGS} -gcflags \"all=-N -l\"" BUILD_DIR="${BUILD_DIR}/debug" build

.PHONY: docker
docker: ## Build a Docker image
	@${MAKE} GOOS=linux GOARCH=amd64 build-release
	docker build -t ${DOCKER_IMAGE} -f Dockerfile .

.PHONY: goversion
goversion:
ifneq (${IGNORE_GOLANG_VERSION_REQ}, 1)
	@printf "${GOLANG_VERSION}\n$$(go version | awk '{sub(/^go/, "", $$3);print $$3}')" | sort -t '.' -k 1,1 -k 2,2 -k 3,3 -g | head -1 | grep -q -E "^${GOLANG_VERSION}$$" || (printf "Required Go version is ${GOLANG_VERSION}\nInstalled: `go version`" && exit 1)
endif

define generate_openapi_client
	@ if [[ "$$OSTYPE" == "linux-gnu" ]]; then sudo rm -rf ${3}; else rm -rf ${3}; fi
	docker run --rm -v $${PWD}:/local openapitools/openapi-generator-cli:${OPENAPI_GENERATOR_VERSION} generate \
	--additional-properties packageName=${2} \
	--additional-properties withGoCodegenComment=true \
	-i /local/${1} \
	-g go \
	-o /local/${3}
	@ if [[ "$$OSTYPE" == "linux-gnu" ]]; then sudo chown -R $(shell id -u):$(shell id -g) ${3}; fi
	rm ${3}/{.travis.yml,git_push.sh,go.*}
	sed -i -- 's/ ImageSource/ *ImageSource/' ${3}/model_image_analysis_request.go
	rm ${3}/model_image_analysis_request.go--
endef

pkg/anchore/swagger.yaml:
	curl https://raw.githubusercontent.com/anchore/anchore-engine/${ANCHORE_VERSION}/anchore_engine/services/apiext/swagger/swagger.yaml | tr '\n' '\r' | sed $$'s/- Images\r      - Vulnerabilities/- Images/g' | tr '\r' '\n' | sed '/- Image Content/d; /- Policy Evaluation/d; /- Queries/d' > pkg/anchore/swagger.yaml

.PHONY: generate-anchore-client
generate-anchore-client: pkg/anchore/swagger.yaml ## Generate client from Anchore OpenAPI spec
	$(call generate_openapi_client,pkg/anchore/swagger.yaml,client,pkg/anchore/client)

.PHONY: help
.DEFAULT_GOAL := help
help:
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'