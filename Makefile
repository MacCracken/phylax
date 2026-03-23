.PHONY: build test check clippy fmt fmt-check clean release audit deny doc coverage all

check: fmt-check clippy test audit

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

test:
	cargo test --workspace

audit:
	cargo audit

deny:
	cargo deny check

coverage:
	cargo llvm-cov --workspace --html --output-dir coverage/

build:
	cargo build --workspace --release

doc:
	RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace

clean:
	cargo clean && rm -rf coverage/

release:
	cargo build --workspace --release

all: check build
