# certop - build y cross-compile

BINARY  := certop
PKG     := ./cmd/certop
DISTDIR := dist
# Version declarada del proyecto. Se le agrega la revision de git cuando el
# arbol de trabajo no coincide con un tag limpio.
VERSION ?= 0.9.1
# Solo la revision: --exclude '*' evita que un tag anotado se cuele aca y
# termine produciendo un "0.9.1+v0.9.1" redundante.
GITREV  := $(shell git describe --always --abbrev=7 --dirty --exclude '*' 2>/dev/null)
ifneq ($(GITREV),)
FULLVERSION := $(VERSION)+$(GITREV)
else
FULLVERSION := $(VERSION)
endif
LDFLAGS := -s -w -X main.version=$(FULLVERSION)
GOFLAGS := CGO_ENABLED=0

# Plataformas de despliegue: los servidores son linux/amd64, las maquinas de
# los operadores son Macs con Apple Silicon.
PLATFORMS := linux/amd64 darwin/arm64

.DEFAULT_GOAL := help

## dist: compila para linux/amd64 y darwin/arm64 en dist/ (target por defecto)
.PHONY: dist
dist: $(PLATFORMS)

.PHONY: $(PLATFORMS)
$(PLATFORMS):
	@mkdir -p $(DISTDIR)
	$(GOFLAGS) GOOS=$(word 1,$(subst /, ,$@)) GOARCH=$(word 2,$(subst /, ,$@)) \
		go build -trimpath -ldflags "$(LDFLAGS)" \
		-o $(DISTDIR)/$(BINARY)-$(word 1,$(subst /, ,$@))-$(word 2,$(subst /, ,$@)) $(PKG)

## build: compila el binario ./certop para la plataforma local
.PHONY: build
build:
	$(GOFLAGS) go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) $(PKG)

## test: corre las pruebas de todos los paquetes
.PHONY: test
test:
	go test ./...

## race: corre las pruebas con el detector de carreras (cubre la UI concurrente)
.PHONY: race
race:
	go test -race ./...

## fmt: reescribe el codigo con gofmt
.PHONY: fmt
fmt:
	gofmt -w $(shell find . -name '*.go' -not -path './vendor/*')

## vet: analisis estatico con go vet
.PHONY: vet
vet:
	go vet ./...

## check: vet + test, sin modificar archivos
.PHONY: check
check: vet test

## clean: borra dist/ y el binario local
.PHONY: clean
clean:
	rm -rf $(DISTDIR) $(BINARY)

## help: muestra esta ayuda
.PHONY: help
help:
	@echo "certop $(FULLVERSION) - targets disponibles"
	@echo
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## //' | \
		awk -F': ' '{ printf "  %-8s %s\n", $$1, substr($$0, index($$0, ": ") + 2) }'
	@echo
	@echo "Tambien se puede compilar una plataforma sola:"
	@for p in $(PLATFORMS); do echo "  make $$p"; done
	@echo
	@echo "Variables:"
	@echo "  VERSION   version del proyecto (default: $(VERSION); se embebe $(FULLVERSION))"
	@echo "  DISTDIR   directorio de salida de dist (default: $(DISTDIR))"
