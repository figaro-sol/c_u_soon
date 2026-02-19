.PHONY: all build-sbf build-sbf-test-programs test test-all test-sdk test-delegation test-macro test-cpi test-security

all: build-sbf test-all

build-sbf:
	cargo build-sbf --manifest-path program/Cargo.toml

build-sbf-test-programs:
	cargo build-sbf --manifest-path test-programs/byte_writer/Cargo.toml
	cargo build-sbf --manifest-path test-programs/attacker_probe/Cargo.toml

test-sdk:
	cargo test -p c_u_soon --features derive
	cargo test -p c_u_soon_client

test-all: test-sdk build-sbf build-sbf-test-programs
	cargo test -p c_u_later
	cargo test --manifest-path program/Cargo.toml

test: test-sdk build-sbf build-sbf-test-programs
	cargo test -p c_u_later
	cargo test --manifest-path program/Cargo.toml

test-macro: build-sbf
	cargo test -p c_u_later

test-delegation: build-sbf
	cargo test --manifest-path program/Cargo.toml --test delegation_security_tests

test-cpi: build-sbf build-sbf-test-programs
	cargo test --manifest-path program/Cargo.toml --test cpi_integration_tests

test-security: build-sbf build-sbf-test-programs
	cargo test --manifest-path program/Cargo.toml --test delegation_security_tests
	cargo test --manifest-path program/Cargo.toml --test cpi_integration_tests
