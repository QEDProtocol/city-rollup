TRACE_ENABLED   := 1

.PHONY: check
check:
	@cargo check --all-targets

.PHONY: fix
fix:
	@cargo fix --all-targets --allow-dirty --allow-staged

.PHONY: fix-typo
fix-typo:
	@typos -w

.PHONY: format
format:
	@cargo fmt

.PHONY: test
test:
	@cargo test -- --nocapture

.PHONY: dedup
dedup:
	@cargo machete --fix

.PHONY: run
run: run-orchestrator run-rpc-server run-l2-worker

.PHONY: run-rpc-server
run-rpc-server:
	@RUST_BACKTRACE=${TRACE_ENABLED} cargo run --package city-rollup-cli rpc-server

.PHONY: run-orchestrator
run-orchestrator:
	@RUST_BACKTRACE=${TRACE_ENABLED} cargo run --package city-rollup-cli orchestrator

.PHONY: run-l2-worker
run-l2-worker:
	@RUST_BACKTRACE=${TRACE_ENABLED} cargo run --package city-rollup-cli l2-worker

.PHONY: run-l2-transfer
run-l2-transfer:
	@RUST_BACKTRACE=${TRACE_ENABLED} cargo run --package city-rollup-cli l2-transfer

.PHONY: print-circuit-info
print-circuit-info:
	@RUST_BACKTRACE=${TRACE_ENABLED} cargo run --package city-rollup-dev-cli print-circuit-info

.PHONY: tree-prove-test
tree-prove-test:
	@RUST_BACKTRACE=${TRACE_ENABLED} cargo run --package city-rollup-dev-cli tree-prove-test

.PHONY: get-public-key
get-public-key:
	@RUST_BACKTRACE=${TRACE_ENABLED} cargo run --package city-rollup-user-cli get-public-key --private-key=2c6a1188f8739daaeff79c40f3690c573381c91a2359a0df2b45e4310b59f30b

.PHONY: random-wallet
random-wallet:
	@RUST_BACKTRACE=${TRACE_ENABLED} cargo run --package city-rollup-user-cli random-wallet

.PHONY: sign-hash
sign-hash:
	@RUST_BACKTRACE=${TRACE_ENABLED} cargo run --package city-rollup-user-cli sign-hash \
		--private-key=2c6a1188f8739daaeff79c40f3690c573381c91a2359a0df2b45e4310b59f30b \
		--action-hash=010d831efabf0bd45a992f203683c1e38a5492054099b29596237efd5e5cdca8 \
		--output=proof.txt

.PHONY: launch
launch:
	@docker-compose \
		-f docker-compose.yml \
		up \
		--build \
		-d \
		--remove-orphans

.PHONY: shutdown
shutdown:
	@docker-compose \
		-f docker-compose.yml \
		down \
		--remove-orphans > /dev/null 2>&1 || true
	@sudo rm -fr chaindata || true
	@sudo rm -fr redis-data || true
	@sudo rm -fr db || true

.PHONY: relaunch
relaunch: shutdown launch

.PHONY: cr_set
cr_set:
	curl http://localhost:3000 \
		-X POST \
		-H "Content-Type: application/json" \
		--data '{"method":"cr_set","params":["abcd","abcd"],"id":1,"jsonrpc":"2.0"}' | jq

.PHONY: cr_get
cr_get:
	curl http://localhost:3000 \
		-X POST \
		-H "Content-Type: application/json" \
		--data '{"method":"cr_get","params":"abcd","id":1,"jsonrpc":"2.0"}' | jq

.PHONY: cr_push
cr_push:
	curl http://localhost:3000 \
		-X POST \
		-H "Content-Type: application/json" \
		--data '{"method":"cr_push","params":[1,"abcd"],"id":1,"jsonrpc":"2.0"}' | jq

.PHONY: cr_pull
cr_pull:
	curl http://localhost:3000 \
		-X POST \
		-H "Content-Type: application/json" \
		--data '{"method":"cr_pull","params":1,"id":1,"jsonrpc":"2.0"}' | jq

.PHONY: cr_register_user
cr_register_user:
	curl http://localhost:3000 \
		-X POST \
		-H "Content-Type: application/json" \
		--data '{"method":"cr_register_user","params":"5f4d13aae1ba684e63b5ce6510ee35722005640d6433bbe56f4c250268efb254","id":1,"jsonrpc":"2.0"}' | jq

.PHONY: cr_token_transfer
cr_token_transfer:
	curl http://localhost:3000 \
		-X POST \
		-H "Content-Type: application/json" \
		--data @proof.json | jq
