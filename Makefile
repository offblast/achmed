IMAGE=quay.io/mischief/achmed

all:	bin docker secrets/secrets.yaml

.PHONY:
bin:	bin/achmed bin/example

.PHONY:
docker:	bin
	docker build -t $(IMAGE) -f Dockerfile .

.PHONY: proto
proto:	proto/achmed.pb.go

proto/achmed.pb.go:	proto/achmed.proto
	protoc -I proto/ proto/achmed.proto --go_out=plugins=grpc:proto

bin/achmed:	proto/achmed.pb.go
	CGO_ENABLED=0 go build -tags netgo -v -o $@ ./cmd/achmed/

bin/example:	proto/achmed.pb.go
	CGO_ENABLED=0 go build -tags netgo -v -o $@ ./_example/cmd/server/

manifests/0-secret.yaml:
	./keygen.sh

.PHONY: kube-down
kube-down:	manifests/0-secret.yaml manifests/*.yaml
	find manifests/ -type f -iname '*.yaml' | sort -nr | tee | xargs -n 1 kubectl delete -f

.PHONY: kube-up
kube-up:	manifests/0-secret.yaml manifests/*.yaml
	find manifests/ -type f -iname '*.yaml' | sort -n | tee | xargs -n 1 kubectl create -f

.PHONY: clean
clean:
	rm -f proto/achmed.pb.go
	rm -f manifests/0-secret.yaml
	rm -rf bin

.PHONY: nuke
nuke:	clean
	rm -rf secrets

