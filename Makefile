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

.PHONY: build
build:
	cargo build --release

.PHONY: build-release-if-not-exists
build-release-if-not-exists:
	if [ ! -f ./target/release/city-rollup-cli ]; then \
		cargo build --release; \
	fi

.PHONY: run
run: run-orchestrator run-rpc-server run-api-server run-l2-worker

.PHONY: run-rpc-server
run-rpc-server: build-release-if-not-exists
	@RUST_BACKTRACE=${TRACE_ENABLED} ./target/release/city-rollup-cli rpc-server

.PHONY: run-api-server
run-api-server: build-release-if-not-exists
	@RUST_BACKTRACE=${TRACE_ENABLED} ./target/release/city-rollup-cli api-server

.PHONY: run-orchestrator
run-orchestrator: build-release-if-not-exists
	@RUST_BACKTRACE=${TRACE_ENABLED} ./target/release/city-rollup-cli orchestrator

.PHONY: run-l2-worker
run-l2-worker: build-release-if-not-exists
	@RUST_BACKTRACE=${TRACE_ENABLED} ./target/release/city-rollup-cli l2-worker

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
	@sudo rm -fr /tmp/plonky2_proof || true
	# @sudo rm -frr /tmp/groth16-keystore || true

.PHONY: relaunch
relaunch: shutdown launch

.PHONY: cr_register_user
cr_register_user:
	@RUST_BACKTRACE=${TRACE_ENABLED} cargo run --release --package city-rollup-user-cli register-user --private-key=2c6a1188f8739daaeff79c40f3690c573381c91a2359a0df2b45e4310b59f30b
	@RUST_BACKTRACE=${TRACE_ENABLED} cargo run --release --package city-rollup-user-cli register-user --private-key=f6648784d8373da16c3e97a860191757c4a88db8d161ede135b22ff879d6cd6d

.PHONY: cr_l1_deposit
cr_l1_deposit:
	@RUST_BACKTRACE=${TRACE_ENABLED} cargo run --release --package city-rollup-user-cli l1-deposit \
		--private-key=2c6a1188f8739daaeff79c40f3690c573381c91a2359a0df2b45e4310b59f30b \
		--amount=1

.PHONY: cr_claim_deposit
cr_claim_deposit:
	@RUST_BACKTRACE=${TRACE_ENABLED} cargo run --release --package city-rollup-user-cli claim-deposit \
		--txid=${TXID} \
		--private-key=2c6a1188f8739daaeff79c40f3690c573381c91a2359a0df2b45e4310b59f30b \
		--user-id=2

.PHONY: cr_token_transfer
cr_token_transfer:
	@RUST_BACKTRACE=${TRACE_ENABLED} cargo run --release --package city-rollup-user-cli token-transfer \
		--private-key=2c6a1188f8739daaeff79c40f3690c573381c91a2359a0df2b45e4310b59f30b \
		--from=2 \
		--to=0 \
		--value=0.5 \
		--nonce=1 \

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
		--data '{"method":"cr_getCityRoot","params":[0],"id":1,"jsonrpc":"2.0"}'  | jq

.PHONY: cr_get_latest_block_state
cr_get_latest_block_state:
	curl http://localhost:3000 \
		-X POST \
		-H "Content-Type: application/json" \
		--data '{"method":"cr_getLatestBlockState","params":[],"id":1,"jsonrpc":"2.0"}'  | jq
