
DOCKER := $(shell which docker)
DOCKER_TAG := arablocks/ann-identity-archiver

docker: Dockerfile
	$(DOCKER) build -t $(DOCKER_TAG) .
