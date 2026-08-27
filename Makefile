.PHONY: test lint

test:
	cargo test --locked --workspace

lint:
	cargo clippy --locked --workspace --all-targets -- -D warnings

.PHONY: test-sdks test-sdks-unit test-blackbox-sdks
test-sdks: test-sdks-unit test-blackbox-sdks

test-sdks-unit:
	cargo test --locked --package abyss-sdk
	npm --prefix sdks/typescript run format:check
	npm --prefix sdks/typescript run lint
	npm --prefix sdks/typescript test
	python3 -m ruff check sdks/python
	python3 -m ruff format --check sdks/python
	PYTHONPATH=sdks/python python3 -m unittest discover -s sdks/python/tests -p 'test_*.py'

test-blackbox-sdks:
	bash scripts/blackbox_sdk_real_broker.sh

.PHONY: test-blackbox-codex-upload test-blackbox-usage-helpers
test-blackbox-codex-upload:
	bash scripts/blackbox_codex_usage_upload.sh

test-blackbox-usage-helpers:
	bash scripts/tests/test_blackbox_usage_helpers.sh

.PHONY: test-blackbox-claude-code-upload
test-blackbox-claude-code-upload:
	bash scripts/blackbox_claude_code_usage_upload.sh

.PHONY: test-blackbox-broker test-blackbox-broker-explicit
test-blackbox-broker: test-blackbox-broker-explicit

test-blackbox-broker-explicit:
	bash scripts/blackbox_abyss_broker_connect.sh

.PHONY: test-blackbox-broker-config-api
test-blackbox-broker-config-api:
	bash scripts/blackbox_abyss_broker_config_api.sh

.PHONY: test-blackbox-macos-ca
test-blackbox-macos-ca:
	bash scripts/blackbox_macos_ca_management.sh

.PHONY: test-local test-local-contract test-blackbox-local
test-local: test-local-contract test-blackbox-local

test-local-contract:
	python3 scripts/tests/test_local_environment_contract.py

test-blackbox-local:
	bash scripts/tests/blackbox_local_environment.sh
