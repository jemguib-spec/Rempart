VERSION ?= 1.1.0
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build build-nohsm test test-hsm vendor install docker docker-softhsm run clean

build:            ## binaire avec support HSM (cgo requis)
	CGO_ENABLED=1 go build -mod=vendor -trimpath -ldflags "$(LDFLAGS)" -o rempart ./cmd/rempart

build-nohsm:      ## binaire statique sans HSM (aucune dépendance système)
	CGO_ENABLED=0 go build -mod=vendor -trimpath -ldflags "$(LDFLAGS)" -o rempart ./cmd/rempart

test:
	go test -mod=vendor ./...

test-hsm:         ## tests PKCS#11 réels (nécessite softhsm2)
	go test -mod=vendor -v -run 'PKCS11|HSM' ./internal/keystore/

vendor:
	go mod tidy && go mod vendor

install:          ## installation guidée (Docker ou Podman), voir scripts/install.sh --help
	./scripts/install.sh

docker:
	docker build --target prod -t rempart:$(VERSION) -t rempart:latest --build-arg VERSION=$(VERSION) .

docker-softhsm:
	docker build --target softhsm -t rempart:softhsm --build-arg VERSION=$(VERSION) .

run: build        ## secrets de développement créés au terminal dans data/secrets (ignoré par git), jamais dans ce fichier
	mkdir -p -m 0700 data/secrets
	./rempart setup-secrets -dir data/secrets -data data
	REMPART_KEYSTORE_PASSPHRASE_FILE=data/secrets/keystore_passphrase \
	REMPART_ADMIN_PASSWORD_FILE=data/secrets/admin_password ./rempart -config rempart.example.yaml

clean:
	rm -rf rempart data
