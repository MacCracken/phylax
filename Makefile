.PHONY: build test check clippy fmt fmt-check clean release audit deny vet doc bench bench-history coverage all

check: fmt-check clippy test audit

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

clippy:
	cargo clippy --all-targets -- -D warnings

test:
	cargo test

audit:
	cargo audit

deny:
	cargo deny check

vet:
	cargo vet --locked

bench:
	cargo bench

bench-history:
	bash scripts/bench-history.sh bench-history.csv bench-latest.md

coverage:
	cargo llvm-cov --html --output-dir coverage/

build:
	cargo build --release

doc:
	RUSTDOCFLAGS="-D warnings" cargo doc --no-deps

clean:
	cargo clean && rm -rf coverage/

all: check build
