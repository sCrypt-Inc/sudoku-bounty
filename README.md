# Private Non-Interactive Bounty for General Computation on Bitcoin

This repository contains Circom and sCrypt code implementing a private non-interactive bounty for solving a Sudoku puzzle via the Bitcoin network. It contains a full end-to-end test along with deployment script examples.

For more information on how the bounty protocol works read our [article on Medium](TODO).

## Testing

Make sure you got Go, Circom and SnarkJS installed and properly configured. Use Circom version 2.0.2.

Get an already prepared power of tau file by running:
```sh
wget https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_22.ptau -O pot22_final.ptau
```

Run tests:
```sh
npm t
```

Tests include a full end-to-end test which takes a long time to process.
