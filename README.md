# City Rollup

a proof of concept zk rollup on dogecoin


## Requirements

- docker
- docker-compose
- rust toolchain


## Getting Started

Download the pre-generated `bls12_381` trust setup

```bash
wget https://city-rollup.s3.amazonaws.com/alpha/groth16-bls12_381-setup.tgz
tar -zxvf groth16-bls12_381-setup.tgz
mkdir -p /tmp/groth16-keystore/
mv trust-setup /tmp/groth16-keystore/0
```

Build the rollup in release mode
```bash
make build
```

Launch dogecoin, electrs, redis and clean old data
```bash
make relaunch
```

Run rpc node to handle rpc requests
```bash
make run-rpc-server
```

Run orchestrator to dispatch proving tasks
```bash
make run-orchestrator
```

Run the worker to handle proving tasks, you can run as many workers as you want
```bash
make run-l2-worker # wait until it successfully loaded the trust setup, often it'll take 3 minutes
#make run-l2-worker
```

Send command to produce the next block and dispatch proving tasks to workers
```bash
make cr_produce_block
```

Register two users on L2
```bash
make cr_register_user
```

Deposit funds from Dogecoin to L2
```bash
make cr_l1_deposit #please copy the txid
```

Produce another block to mark the deposits as claimable on L2
```bash
make cr_produce_block
```

Claim deposited funds
```bash
make TXID=... cr_claim_deposit #no 0x prefix
```

Transfer claimed funds from to another
```bash
make cr_token_transfer
```

Produce another block
```bash
make cr_produce_block
```

## Docker(experimental)


Download the pre-generated `bls12_381` trust setup

```bash
wget https://city-rollup.s3.amazonaws.com/alpha/groth16-bls12_381-setup.tgz
tar -zxvf groth16-bls12_381-setup.tgz
mkdir -p /tmp/groth16-keystore/
mv trust-setup /tmp/groth16-keystore/0
```

Build the rollup in release mode
```bash
make build
```

Launch
```bash
make DOCKER_PROFILE=full relaunch
```


## Troubleshot

If you encounter the `DER` error on cli tools, it's normal, don't panic just retry until it works
```bash
Error: AnyhowError(error in BTCDataResolver: {"result":null,"error":{"code":-26,"message":"64: non-mandatory-script-verify-flag (Non-canonical DER signature)"},"id":1}
```

If you encounter the `Insufficient funds` error on orchestrator, don't panic just retry until it works, it's something wierd with confirmations that we didn't fix yet
```bash
Error: Failed to fund address: {"result":null,"error":{"code":-6,"message":"Insufficient funds"},"id":1}
```

If you encounter constraint error while claiming deposit, don't panic just retry
```bash
assertion `left == right` failed: Partition containing Wire(Wire { row: 3087, column: 38 }) was set twice with different values: 11780246312495197923 != 4265533886750191950
  left: 4265533886750191950
 right: 11780246312495197923
```
