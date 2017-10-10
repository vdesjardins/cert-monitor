GO_EXEC ?= go
VERSION ?= $(shell git describe --tags)

build:
	${GO_EXEC} build -ldflags "-X main.version=${VERSION}"

install: build
	install -d ${DESTDIR}/usr/sbin/
	install -m 755 ./cert-monitor ${DESTDIR}/usr/sbin/cert-monitor

test:
	${GO_EXEC} test ./vault ./config

clean:
	rm ./cert-monitor

.PHONY: build test install clean
