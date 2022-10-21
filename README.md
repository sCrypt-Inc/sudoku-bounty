Make sure you got go, circom and snarkjs installed.

Download the sCrypt compiler binary:
```sh
npx scryptlib download 
```

Get ptau file by running:
```sh
wget https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_22.ptau -O pot22_final.ptau
```

Run tests:
```sh
npm run test
```

Tests include a full end-to-end test which takes a long time to process.
