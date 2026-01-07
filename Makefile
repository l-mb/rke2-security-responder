.PHONY: all build test clean lint helm-lint docker-build

BINARY_NAME=security-responder
DOCKER_REPO=rancher/rke2-security-responder
VERSION?=v0.1.0

all: build

build:
	go build -o $(BINARY_NAME) main.go

test:
	go test -v ./...

clean:
	rm -f $(BINARY_NAME)
	rm -rf dist/

lint:
	golangci-lint run

helm-lint:
	helm lint charts/rke2-security-responder

helm-template:
	helm template rke2-security-responder charts/rke2-security-responder \
		--namespace kube-system

docker-build:
	docker build -t $(DOCKER_REPO):$(VERSION) .
	docker tag $(DOCKER_REPO):$(VERSION) $(DOCKER_REPO):latest

fmt:
	go fmt ./...

vet:
	go vet ./...
