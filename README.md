# City Rollup

a proof of concept zk rollup on dogecoin


## Requirements

- docker
- docker-compose
- rust toolchain


## Getting Started

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

Send command to produce the next block and dispatch proving works to workers
```bash
make cr_produce_block
```

Register two users on L2
```bash
make cr_register_user
```

Deposit funds from Dogecoin to L2
```bash
make cr_l1_deposit
```

Produce another block to mark the deposits as claimable
```bash
make cr_produce_block
```

Claim deposited funds
```bash
make TXID=0x... cr_claim_deposit
```

Transfer claimed funds from to another
```bash
make cr_token_transfer
```
