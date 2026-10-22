.PHONY: all build fmt lint clean install

BIN    := /usr/local/bin/bfloginauth
CONFIG := /etc/bfloginauth/bfloginauth.toml
# Release archive: binary next to the Makefile; source checkout: cargo build output.
SRC    := $(firstword $(wildcard bfloginauth) target/release/bfloginauth)

all: build

build: fmt
	cargo build --release

fmt:
	cargo fmt

lint:
	cargo clippy -- -D warnings

clean:
	cargo clean

# Source: make && sudo make install / release archive: sudo make install
install:
	install -m 0755 $(SRC) $(BIN)
	id bfloginauth >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin bfloginauth
	install -d -o bfloginauth -g bfloginauth -m 0700 /etc/bfloginauth
	test -f $(CONFIG) || sudo -u bfloginauth $(BIN) -c $(CONFIG) init
	install -m 0644 deploy/bfloginauth.service /etc/systemd/system/bfloginauth.service
	systemctl daemon-reload
	if [ -d /etc/nginx ]; then install -d /etc/nginx/snippets /etc/nginx/conf.d; \
	  for f in deploy/nginx/snippets/*.conf; do test -f /etc/nginx/snippets/$$(basename $$f) || install -m 0644 $$f /etc/nginx/snippets/; done; \
	  for f in deploy/nginx/conf.d/*.conf; do test -f /etc/nginx/conf.d/$$(basename $$f) || install -m 0644 $$f /etc/nginx/conf.d/; done; fi
	@echo "first install: systemctl enable --now bfloginauth / update: systemctl restart bfloginauth"
