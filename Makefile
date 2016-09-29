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

secrets/secrets.yaml:
	./keygen.sh

.PHONY: kube-down
kube-down:	secrets/secrets.yaml
	kubectl delete -f example.yaml -f achmed.yaml -f secrets/secrets.yaml

.PHONY: kube-up
kube-up:	secrets/secrets.yaml achmed.yaml example.yaml
	kubectl create -f secrets/secrets.yaml -f achmed.yaml -f example.yaml

.PHONY: clean
clean:
	rm -f proto/achmed.pb.go
	rm -f secrets/secrets.yaml
	rm -rf bin

.PHONY: nuke
nuke:
	rm -rf secrets

