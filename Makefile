.PHONY: all build-sbf test test-all test-delegation test-macro test-cpi test-security

all: build-sbf test-all

build-sbf:
	cargo build-sbf --manifest-path program/Cargo.toml

test-all: build-sbf
	cargo test -p c_u_later
	cargo test --manifest-path program/Cargo.toml

test: build-sbf
	cargo test -p c_u_later
	cargo test --manifest-path program/Cargo.toml

test-macro: build-sbf
	cargo test -p c_u_later

test-delegation: build-sbf
	cargo test --manifest-path program/Cargo.toml --test delegation_security_tests

test-cpi: build-sbf
	cargo test --manifest-path program/Cargo.toml --test cpi_integration_tests

test-security: build-sbf
	cargo test --manifest-path program/Cargo.toml --test delegation_security_tests
	cargo test --manifest-path program/Cargo.toml --test cpi_integration_tests
