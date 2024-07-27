TRACE_ENABLED           := full
PROFILE                 := release
LOG_LEVEL  			        := info,city_common_circuit=off,city_rollup_circuit=off,plonky2=off,city_crypto=off,city_store=off,city_rollup_common=off

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
	cargo build --${PROFILE}

.PHONY: build-if-not-exists
build-if-not-exists:
	@if [ ! -f ./target/${PROFILE}/city-rollup-cli ] || [ ! -f ./target/${PROFILE}/city-rollup-user-cli ] || [ ! -f ./target/${PROFILE}/city-rollup-dev-cli ]; then \
		echo "Building project for profile ${PROFILE}..."; \
		cargo build --${PROFILE}; \
	fi

.PHONY: run
run: run-orchestrator run-rpc-server run-l2-worker

.PHONY: run-rpc-server
run-rpc-server: build-if-not-exists
	@RUST_LOG=${LOG_LEVEL} RUST_BACKTRACE=${TRACE_ENABLED} ./target/${PROFILE}/city-rollup-cli rpc-server

.PHONY: run-orchestrator
run-orchestrator: build-if-not-exists
	@RUST_LOG=${LOG_LEVEL} RUST_BACKTRACE=${TRACE_ENABLED} ./target/${PROFILE}/city-rollup-cli orchestrator

.PHONY: run-l2-worker
run-l2-worker: build-if-not-exists
	@RUST_LOG=${LOG_LEVEL} RUST_BACKTRACE=${TRACE_ENABLED} ./target/${PROFILE}/city-rollup-cli l2-worker --debug-mode 1

.PHONY: run-l2-worker-g16
run-l2-worker-g16: build-if-not-exists
	@RUST_LOG=${LOG_LEVEL} RUST_BACKTRACE=${TRACE_ENABLED} ./target/${PROFILE}/city-rollup-cli l2-worker --debug-mode 1 --worker-mode only-groth16

.PHONY: run-l2-worker-no-g16
run-l2-worker-no-g16: build-if-not-exists
	@RUST_LOG=${LOG_LEVEL} RUST_BACKTRACE=${TRACE_ENABLED} ./target/${PROFILE}/city-rollup-cli l2-worker --worker-mode no-groth16

.PHONY: print-circuit-info
print-circuit-info: build-if-not-exists
	@RUST_LOG=${LOG_LEVEL} RUST_BACKTRACE=${TRACE_ENABLED} ./target/${PROFILE}/city-rollup-dev-cli print-circuit-info

.PHONY: tree-prove-test
tree-prove-test: build-if-not-exists
	@RUST_LOG=${LOG_LEVEL} RUST_BACKTRACE=${TRACE_ENABLED} ./target/${PROFILE}/city-rollup-dev-cli tree-prove-test

.PHONY: get-public-key
get-public-key: build-if-not-exists
	@RUST_LOG=${LOG_LEVEL} RUST_BACKTRACE=${TRACE_ENABLED} ./target/${PROFILE}/city-rollup-user-cli get-public-key --private-key=2c6a1188f8739daaeff79c40f3690c573381c91a2359a0df2b45e4310b59f30b

.PHONY: random-wallet
random-wallet: build-if-not-exists
	@RUST_LOG=${LOG_LEVEL} RUST_BACKTRACE=${TRACE_ENABLED} ./target/${PROFILE}/city-rollup-user-cli random-wallet

.PHONY: sign-hash
sign-hash: build-if-not-exists
	@RUST_LOG=${LOG_LEVEL} RUST_BACKTRACE=${TRACE_ENABLED} ./target/${PROFILE}/city-rollup-user-cli sign-hash \
		--private-key=2c6a1188f8739daaeff79c40f3690c573381c91a2359a0df2b45e4310b59f30b \
		--action-hash=010d831efabf0bd45a992f203683c1e38a5492054099b29596237efd5e5cdca8 \
		--output=proof.txt

.PHONY: full_block
full_block: build-if-not-exists
	@RUST_LOG=${LOG_LEVEL} RUST_BACKTRACE=${TRACE_ENABLED} ./target/${PROFILE}/city-rollup-dev-cli --example full_block

.PHONY: full_block2
full_block2: build-if-not-exists
	@RUST_LOG=${LOG_LEVEL} RUST_BACKTRACE=${TRACE_ENABLED} ./target/${PROFILE}/city-rollup-dev-cli --example full_block_v2

.PHONY: fblockredis
fblockredis: build-if-not-exists
	@RUST_LOG=${LOG_LEVEL} RUST_BACKTRACE=${TRACE_ENABLED} ./target/${PROFILE}/city-rollup-dev-cli --example fblockredis

.PHONY: hashes
hashes: build-if-not-exists
	@RUST_LOG=${LOG_LEVEL} RUST_BACKTRACE=${TRACE_ENABLED} ./target/${PROFILE}/city-rollup-dev-cli --example hashes

.PHONY: print_hints
print_hints: build-if-not-exists
	@RUST_LOG=${LOG_LEVEL} RUST_BACKTRACE=${TRACE_ENABLED} ./target/${PROFILE}/city-rollup-dev-cli --example print_hints

.PHONY: prove_sighash_0_hints
prove_sighash_0_hints: build-if-not-exists
	@RUST_LOG=${LOG_LEVEL} RUST_BACKTRACE=${TRACE_ENABLED} ./target/${PROFILE}/city-rollup-dev-cli --example prove_sighash_0_hints

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
	@sudo rm -fr /tmp/plonky2_proof || true
	# @sudo rm -fr ~/.dogecoin || true
	# @sudo rm -fr ~/.city-rollup/keystore || true

.PHONY: relaunch
relaunch: shutdown launch

.PHONY: cr_register_user
cr_register_user: build-if-not-exists
	@RUST_LOG=${LOG_LEVEL} RUST_BACKTRACE=${TRACE_ENABLED} ./target/${PROFILE}/city-rollup-user-cli register-user --private-key=2c6a1188f8739daaeff79c40f3690c573381c91a2359a0df2b45e4310b59f30b

.PHONY: cr_l1_deposit
cr_l1_deposit: build-if-not-exists
	@RUST_LOG=${LOG_LEVEL} RUST_BACKTRACE=${TRACE_ENABLED} ./target/${PROFILE}/city-rollup-user-cli l1-deposit \
		--private-key=2c6a1188f8739daaeff79c40f3690c573381c91a2359a0df2b45e4310b59f30b \
		--amount=100000000

.PHONY: cr_l1_refund
cr_l1_refund: build-if-not-exists
	@RUST_LOG=${LOG_LEVEL} RUST_BACKTRACE=${TRACE_ENABLED} ./target/${PROFILE}/city-rollup-user-cli l1-refund \
		--private-key=2c6a1188f8739daaeff79c40f3690c573381c91a2359a0df2b45e4310b59f30b \
		--txid=${TXID} \
		--index=0

.PHONY: cr_claim_deposit
cr_claim_deposit: build-if-not-exists
	@RUST_LOG=${LOG_LEVEL} RUST_BACKTRACE=${TRACE_ENABLED} ./target/${PROFILE}/city-rollup-user-cli claim-deposit \
		--txid=${TXID} \
		--private-key=2c6a1188f8739daaeff79c40f3690c573381c91a2359a0df2b45e4310b59f30b \
		--user-id=2

.PHONY: cr_token_transfer
cr_token_transfer: build-if-not-exists
	@RUST_LOG=${LOG_LEVEL} RUST_BACKTRACE=${TRACE_ENABLED} ./target/${PROFILE}/city-rollup-user-cli token-transfer \
		--private-key=2c6a1188f8739daaeff79c40f3690c573381c91a2359a0df2b45e4310b59f30b \
		--from=2 \
		--to=0 \
		--value=50000000 \
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

.PHONY: cr_get_deposit_by_txid
cr_get_deposit_by_txid:
	curl http://localhost:3000 \
		-X POST \
		-H "Content-Type: application/json" \
		--data '{"method":"cr_getDepositByTxid","params":["5096eab42d26997ef450567e3c1fd9646b31910fbfc71700affa8a0346fa4e5c"],"id":1,"jsonrpc":"2.0"}'  | jq

.PHONY: cr_get_deposit_by_id
cr_get_deposit_by_id:
	curl http://localhost:3000 \
		-X POST \
		-H "Content-Type: application/json" \
		--data '{"method":"cr_getDepositById","params":[4,0],"id":1,"jsonrpc":"2.0"}'  | jq

.PHONY: cr_get_user_by_id
cr_get_user_by_id:
	curl http://localhost:3000 \
		-X POST \
		-H "Content-Type: application/json" \
		--data '{"method":"cr_getUserById","params":[4,2],"id":1,"jsonrpc":"2.0"}'  | jq

.PHONY: image
image:
	docker build \
		-c 512 \
		-t qedprotocol/city-rollup:latest \
		-f Dockerfile .
