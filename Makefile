.PHONY: build test check clippy fmt clean release

build:
	cargo build --workspace

test:
	cargo test --workspace

check:
	cargo check --workspace

clippy:
	cargo clippy --workspace -- -D warnings

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

clean:
	cargo clean

release:
	cargo build --workspace --release

all: fmt clippy test build
