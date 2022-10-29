
import path = require("path");
import fs from "fs";
import { execSync } from 'child_process';

import { SyncRequestClient } from 'ts-sync-request/dist';

import {
    buildContractClass, buildTypeClasses,
    hash160, Ripemd160, bsv, getPreimage, sha256,
    buildPublicKeyHashScript, Sha256, compile, findCompiler
} from "scryptlib";

import { Point } from '@noble/secp256k1';
import { poseidonEncrypt, formatSharedKey } from '../test/ts/util/poseidonEncryption';

import { bigIntToArray, vKeyToSCryptType, proofToSCryptType } from '../test/ts/util/misc';
import { DEFAULT_FLAGS, DEFAULT_SIGHASH_TYPE } from "scryptlib/dist/utils";


///// ADJUST: ///////////////////////////////////////////////////////////////////////////////
//const network = 'test';
const network = 'main';
const taalAPIKey = '';

const contractTxId = '8e524b7de2f42cf45daf2851e00161ee6984780c464e484b88b34bb6c629911f';
const contractTxOutIdx = 0;

const fundAddr = '1CuXp3tbHfBa9UDxBVdz8vBSE8LHVjxZ3n';
const fundPrivKey = bsv.PrivateKey('');
const fundPubKey = fundPrivKey.toPublicKey();

const fundingTxId = 'c8ddf762d1244f4ba449aa93d555bf67159d1925aa705ff36453f6b7682c18af';
const fundingTxIdxOut = 0;

// In a "real world" scenario you would probably wan't to extract these from the contract TX itself.
const da: bigint = 88549154299169935420064281163296845505587953610183896504176354567359434168161n;
const Qa: Point = Point.fromPrivateKey(da);
const QaxArray = bigIntToArray(64, 4, Qa.x);
const QayArray = bigIntToArray(64, 4, Qa.y);
const rewardSats = 10000;
const contractExpireBlock = 763000;

let w = [
    [1, 8, 4, 3, 7, 6, 2, 9, 5],
    [5, 3, 7, 2, 9, 1, 8, 4, 6],
    [9, 2, 6, 8, 4, 5, 7, 1, 3],
    [3, 6, 5, 7, 1, 8, 4, 2, 9],
    [2, 7, 8, 4, 6, 9, 5, 3, 1],
    [4, 1, 9, 5, 3, 2, 6, 7, 8],
    [6, 5, 3, 1, 2, 4, 9, 8, 7],
    [8, 4, 1, 9, 5, 7, 3, 6, 2],
    [7, 9, 2, 6, 8, 3, 1, 5, 4],
];
let wFlattened = w.reduce((accumulator: any, value: any) => accumulator.concat(value), []);

let db: bigint = 90388020393783788847120091912026443124559466591761394939671630294477859800601n;
let Qb: Point = Point.fromPrivateKey(db);
/////////////////////////////////////////////////////////////////////////////////////////////

let Qs: Point = Qb.multiply(da);

let dbArray = bigIntToArray(64, 4, db);
let QbxArray = bigIntToArray(64, 4, Qb.x);
let QbyArray = bigIntToArray(64, 4, Qb.y);
let QsxArray = bigIntToArray(64, 4, Qs.x);
let QsyArray = bigIntToArray(64, 4, Qs.y);

//let nonce = BigInt(Math.floor(Date.now() / 1000));
let nonce = BigInt(1234);
let ew = poseidonEncrypt(wFlattened, formatSharedKey(QsxArray), nonce);

let QaHex = Qa.toHex(false).slice(2);  // Slice away "04" at the beggining from uncompressed encoding.
let QbHex = Qb.toHex(false).slice(2);

let nonceHex = nonce.toString(16);
nonceHex = "0".repeat(64 - nonceHex.length) + nonceHex;

let ewHex = '';
for (var i = 0; i < ew.length; i++) {
    let partStr = ew[i].toString(16);
    ewHex += "0".repeat(64 - partStr.length) + partStr;
}
let pubInputsHex = QaHex + QbHex + nonceHex + ewHex;
let Hpub = sha256(pubInputsHex);
let Hpub0 = BigInt('0x' + Hpub.substring(0, 32));
let Hpub1 = BigInt('0x' + Hpub.substring(32, 64));

// Compile circuit.
let circuitPath = path.join(__dirname, 'circuits', 'test_main.circom');
let output = execSync(`circom ${circuitPath} --r1cs --wasm --sym`).toString();
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

// Generate proof.
let witness = {
    "w": w,
    "db": dbArray,
    "Qs": [QsxArray, QsyArray],
    "Qa": [QaxArray, QayArray],
    "Qb": [QbxArray, QbyArray],
    "nonce": nonce,
    "ew": ew,
    "Hpub": [Hpub0, Hpub1]
};

fs.writeFileSync("input.json", JSON.stringify(witness, (key: any, value: any) =>
    typeof value === 'bigint'
        ? value.toString()
        : value // return everything else unchanged
));

output = execSync(`node test_main_js/generate_witness.js test_main_js/test_main.wasm input.json witness.wtns`).toString();
console.log(output);
output = execSync(`snarkjs groth16 prove circuit_0000.zkey witness.wtns proof.json public.json`).toString();
console.log(output);
let proof = JSON.parse(fs.readFileSync("proof.json").toString());

let newLockingScript = buildPublicKeyHashScript(new Ripemd160(hash160(
    "04" + Qb.x.toString(16) + Qb.y.toString(16)
)));

let inputSatoshis = rewardSats;

let utxo = {
    txId: contractTxId,
    outputIndex: contractTxOutIdx,
    script: infoBounty.lockingScript,
    satoshis: inputSatoshis
};
let tx = new bsv.Transaction().from(utxo);

let response: any = new SyncRequestClient().get(`https://api.whatsonchain.com/v1/bsv/${network}/tx/hash/${fundingTxId}`);
let fundingTxLs = bsv.Script(response.vout[fundingTxIdxOut].scriptPubKey.hex);
let fundingAmount = Math.round(response.vout[fundingTxIdxOut].value * 100 * 10 ** 6);
tx.addInput(new bsv.Transaction.Input.PublicKeyHash({
    prevTxId: fundingTxId,
    outputIndex: 0,
    script: null
}), fundingTxLs, fundingAmount);

tx.addOutput(new bsv.Transaction.Output({
    script: newLockingScript,
    satoshis: rewardSats
}))

let dataOutScript = "006a" + pubInputsHex;

tx.addOutput(new bsv.Transaction.Output({
    script: dataOutScript,
    satoshis: 0
}))

let preimage = getPreimage(tx, infoBounty.lockingScript, inputSatoshis)

const uls = infoBounty.unlock(
    new ContractTypes.ECPoint({ x: QbxArray, y: QbyArray }),
    ew,
    new Sha256(Hpub),
    nonce,
    proofToSCryptType(proof, ContractTypes),
    preimage).unlockingScript;

tx.inputs[0].setScript(uls);

let sig = {
    inputIndex: 1,
    sigtype: DEFAULT_SIGHASH_TYPE,
    publicKey: fundPubKey,
    signature: bsv.Transaction.sighash.sign(
        tx, fundPrivKey, DEFAULT_SIGHASH_TYPE,
        1, fundingTxLs, new bsv.crypto.BN(fundingAmount), DEFAULT_FLAGS)
};
tx.applySignature(sig);

//console.log(tx.inputs[1].isFullySigned());

response = new SyncRequestClient()
    .addHeader("Content-Type", "application/json")
    .addHeader("Authorization", taalAPIKey)
    .post("https://api.taal.com/api/v1/broadcast",
        { "rawTx": tx.toString() });
console.log(response);
