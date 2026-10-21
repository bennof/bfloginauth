.PHONY: all build fmt lint clean install

BIN    := /usr/local/bin/bfloginauth
CONFIG := /etc/bfloginauth/bfloginauth.toml

all: build

build: fmt
	cargo build --release

fmt:
	cargo fmt

lint:
	cargo clippy -- -D warnings

clean:
	cargo clean

# make && sudo make install
install:
	install -m 0755 target/release/bfloginauth $(BIN)
	id bfloginauth >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin bfloginauth
	install -d -o bfloginauth -g bfloginauth -m 0700 /etc/bfloginauth
	test -f $(CONFIG) || sudo -u bfloginauth $(BIN) -c $(CONFIG) init
	install -m 0644 examples/bfloginauth.service /etc/systemd/system/bfloginauth.service
	systemctl daemon-reload
	if [ -d /etc/nginx ]; then install -d /etc/nginx/snippets; \
	  for f in nginx/snippets/*.conf; do test -f /etc/nginx/snippets/$$(basename $$f) || install -m 0644 $$f /etc/nginx/snippets/; done; fi
	@echo "first install: systemctl enable --now bfloginauth / update: systemctl restart bfloginauth"
