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

Launch bitide, redis and clean old data
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
make run-l2-worker
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

If you encounter the `DER` error, it's normal, don't panic just relaunch until it works
```bash
Error: AnyhowError(error in BTCDataResolver: {"result":null,"error":{"code":-26,"message":"64: non-mandatory-script-verify-flag (Non-canonical DER signature)"},"id":1}
```

If you encounter the `Insufficient funds` error, it's not your lucky day, try to test on another day  
or relaunch until it works. However, this is a tiny error that we didn't fix yet
