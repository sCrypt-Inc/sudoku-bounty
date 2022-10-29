import path = require("path");
import fs from "fs";
import { execSync } from 'child_process';

import { SyncRequestClient } from 'ts-sync-request/dist';

import {
  buildContractClass, buildTypeClasses,
  bsv, findCompiler, compile
} from "scryptlib";

import { Point } from '@noble/secp256k1';

import { bigIntToArray, vKeyToSCryptType } from '../test/ts/util/misc';
import { DEFAULT_FLAGS, DEFAULT_SIGHASH_TYPE } from "scryptlib/dist/utils";


///// ADJUST: ///////////////////////////////////////////////////////////////////////////////
//const network = 'test';
const network = 'main';
const taalAPIKey = '';

const fundAddr = '1CuXp3tbHfBa9UDxBVdz8vBSE8LHVjxZ3n';
const fundPrivKey = bsv.PrivateKey('');
const fundPubKey = fundPrivKey.toPublicKey();

const fundingTxId = '618cd4b61d7e25f9211d17af2e549b4f3ab1160bb89e2b407103e9c94c597d28';
const fundingTxIdxOut = 0;

const da: bigint = 88549154299169935420064281163296845505587953610183896504176354567359434168161n;
const Qa: Point = Point.fromPrivateKey(da);
const QaxArray = bigIntToArray(64, 4, Qa.x);
const QayArray = bigIntToArray(64, 4, Qa.y);

const rewardSats = 10000;
const contractExpireBlock = 763000;
/////////////////////////////////////////////////////////////////////////////////////////////


// Compile circuit.
let circuitPath = path.join(__dirname, 'circuits', 'test_main.circom');
let output = execSync(`circom ${circuitPath} --r1cs --wasm --sym`).toString();
console.log(output);

output = execSync(`snarkjs groth16 setup test_main.r1cs pot22_final.ptau circuit_0000.zkey`).toString();
console.log(output);

// IMPORTANT: When using Groth16 in production you need a phase 2 contribution here:
// https://github.com/iden3/snarkjs#groth16

output = execSync(`snarkjs zkey export verificationkey circuit_0000.zkey verification_key.json`).toString();
console.log(output);

let vKey = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "verification_key.json")).toString());

// Compile sCrypt conract.
let filePath = path.join(__dirname, '..', 'contracts', 'bounty.scrypt');
let out = path.join(__dirname, '..', 'out-scrypt');
if (!fs.existsSync(out)) {
  fs.mkdirSync(out);
}

//let result = compileContract(filePath, { out: out, desc: true });
let result = compile(
  { path: filePath },
  {
    desc: true,
    asm: false,
    ast: true,
    debug: false,
    hex: true,
    stdout: false,
    outputDir: out,
    outputToFiles: false,
    cmdPrefix: findCompiler(),
    timeout: 7200000
  }
);

if (result.errors.length > 0) {
    console.log(`Compile contract ${filePath} failed: `, result.errors);
    throw result.errors;
}
const InformationBounty = buildContractClass(result);

//const desc = JSON.parse(fs.readFileSync(path.join(out, "bounty_desc.json")).toString());
//const InformationBounty = buildContractClass(desc);

const ContractTypes = buildTypeClasses(InformationBounty);

let infoBounty = new InformationBounty(
  new ContractTypes.ECPoint({ x: QaxArray, y: QayArray }),
  vKeyToSCryptType(vKey, ContractTypes),
  rewardSats,
  contractExpireBlock
);

let response: any = new SyncRequestClient().get(`https://api.whatsonchain.com/v1/bsv/${network}/tx/hash/${fundingTxId}`);
let fundingTxLs = bsv.Script(response.vout[fundingTxIdxOut].scriptPubKey.hex);
let fundingAmount = Math.floor(response.vout[fundingTxIdxOut].value * 100 * 10 ** 6);
let tx = new bsv.Transaction()
  .from({
    'txId': fundingTxId,
    'outputIndex': fundingTxIdxOut,
    'script': fundingTxLs,
    'satoshis': fundingAmount
  });

tx.addOutput(new bsv.Transaction.Output({
  script: infoBounty.lockingScript,
  satoshis: new bsv.crypto.BN(rewardSats)
}));

let sig = {
  inputIndex: 0,
  sigtype: DEFAULT_SIGHASH_TYPE,
  publicKey: fundPubKey,
  signature: bsv.Transaction.sighash.sign(
    tx, fundPrivKey, DEFAULT_SIGHASH_TYPE,
    0, fundingTxLs, new bsv.crypto.BN(fundingAmount), DEFAULT_FLAGS)
};
tx.applySignature(sig);

let minFee = ((tx.toString().length / 2) / 1000) * 50;
console.log(minFee)

response = new SyncRequestClient()
  .addHeader("Content-Type", "application/json")
  .addHeader("Authorization", taalAPIKey)
  .post("https://api.taal.com/api/v1/broadcast",
    { "rawTx": tx.toString() });
console.log(response);
