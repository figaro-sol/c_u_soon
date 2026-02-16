.PHONY: all build-sbf test test-all

all: build-sbf test-all

build-sbf:
	cargo build-sbf --manifest-path program/Cargo.toml

test-all: build-sbf
	cargo test --manifest-path program/Cargo.toml

test: build-sbf
	cargo test --manifest-path program/Cargo.toml
