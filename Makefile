TRACE_ENABLED   := 1

.PHONY: check
check:
	@cargo check --all-targets --examples

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
	@RUST_BACKTRACE=${TRACE_ENABLED} cargo run --release --package city-rollup-cli rpc-server

.PHONY: run-api-server
run-api-server:
	@RUST_BACKTRACE=${TRACE_ENABLED} cargo run --release --package city-rollup-cli api-server

.PHONY: run-orchestrator
run-orchestrator:
	@RUST_BACKTRACE=${TRACE_ENABLED} cargo run --release --package city-rollup-cli orchestrator

.PHONY: run-l2-worker
run-l2-worker:
	@RUST_BACKTRACE=${TRACE_ENABLED} cargo run --release --package city-rollup-cli l2-worker

.PHONY: run-l2-transfer
run-l2-transfer:
	@RUST_BACKTRACE=${TRACE_ENABLED} cargo run --release --package city-rollup-cli l2-transfer

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

.PHONY: full_block
full_block:
	@RUST_BACKTRACE=${TRACE_ENABLED} cargo run --package city-rollup-dev-cli --example full_block

.PHONY: full_block2
full_block2:
	@RUST_BACKTRACE=${TRACE_ENABLED} cargo run --package city-rollup-dev-cli --example full_block_v2

.PHONY: fblockredis
fblockredis:
	@RUST_BACKTRACE=${TRACE_ENABLED} cargo run --package city-rollup-dev-cli --example fblockredis

.PHONY: hashes
hashes:
	@RUST_BACKTRACE=${TRACE_ENABLED} cargo run --package city-rollup-dev-cli --example hashes

.PHONY: print_hints
print_hints:
	@RUST_BACKTRACE=${TRACE_ENABLED} cargo run --package city-rollup-dev-cli --example print_hints

.PHONY: prove_sighash_0_hints
prove_sighash_0_hints:
	@RUST_BACKTRACE=${TRACE_ENABLED} cargo run --package city-rollup-dev-cli --example prove_sighash_0_hints

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
	@sudo rm -fr redis-data || true
	@sudo rm -fr db || true

.PHONY: relaunch
relaunch: shutdown launch

.PHONY: cr_register_user
cr_register_user:
	curl http://localhost:3000 \
		-X POST \
		-H "Content-Type: application/json" \
		--data '{"method":"cr_register_user","params":"754b90a6bc1ff9f726ea83ebc652d48747520192712f97f7adc9387ec1b7d761","id":1,"jsonrpc":"2.0"}'
	sleep 1
	curl http://localhost:3000 \
		-X POST \
		-H "Content-Type: application/json" \
		--data '{"method":"cr_register_user","params":"98d582128608b29c76f26372ccc20f4f23b3d5628cc1391251a15306e017343d","id":1,"jsonrpc":"2.0"}'
	sleep 1
	curl http://localhost:3000 \
		-X POST \
		-H "Content-Type: application/json" \
		--data '{"method":"cr_register_user","params":"6c4b61af0b650c1beb103e702474223531e83f75f56ea730ddb4fd2109909f37","id":1,"jsonrpc":"2.0"}'

.PHONY: cr_token_transfer
cr_token_transfer:
	curl http://localhost:3000 \
		-X POST \
		-H "Content-Type: application/json" \
		--data @static/token_transfer.json | jq

.PHONY: cr_produce_block
cr_produce_block:
	curl http://localhost:3000 \
		-X POST \
		-H "Content-Type: application/json" \
		--data '{"method":"cr_produce_block","params":null,"id":1,"jsonrpc":"2.0"}'  | jq

.PHONY: cr_get_city_root
cr_get_city_root:
	curl http://localhost:3000 \
		-X POST \
		-H "Content-Type: application/json" \
		--data '{"method":"cr_getCityRoot","params":0,"id":1,"jsonrpc":"2.0"}'  | jq
