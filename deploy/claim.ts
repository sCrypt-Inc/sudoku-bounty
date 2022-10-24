
import path = require("path");
import fs from "fs";
import { execSync } from 'child_process';

import { SyncRequestClient } from 'ts-sync-request/dist';

import {
    buildContractClass, buildTypeClasses,
    hash160, Ripemd160, bsv, getPreimage, sha256,
    buildPublicKeyHashScript, Sha256
} from "scryptlib";

import { Point } from '@noble/secp256k1';
import { poseidonEncrypt, formatSharedKey } from '../test/ts/util/poseidonEncryption';

import { bigIntToArray, bigIntToHexStrFixedLen, vKeyToSCryptType, proofToSCryptType } from '../test/ts/util/misc';


const network = 'main';
const taalAPIKey = '';

const contractTxId = '618cd4b61d7e25f9211d17af2e549b4f3ab1160bb89e2b407103e9c94c597d28';
const contractTxOutIdx = 0;

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

let Qs: Point = Qb.multiply(da);

let dbArray = bigIntToArray(64, 4, db);
let QbxArray = bigIntToArray(64, 4, Qb.x);
let QbyArray = bigIntToArray(64, 4, Qb.y);
let QsxArray = bigIntToArray(64, 4, Qs.x);
let QsyArray = bigIntToArray(64, 4, Qs.y);

let nonce = BigInt(Math.floor(Date.now() / 1000));
let ew = poseidonEncrypt(wFlattened, formatSharedKey(QsxArray), nonce);

let ewHex = '';
for (var i = 0; i < ew.length; i++) {
    let partStr = ew[i].toString(16);
    ewHex += "0".repeat(64 - partStr.length) + partStr;
}
let Hew = sha256(ewHex);
let Hew0 = BigInt('0x' + Hew.substring(0, 32));
let Hew1 = BigInt('0x' + Hew.substring(32, 64));


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
//let result = compile(
//  { path: filePath },
//  {
//    desc: true,
//    asm: false,
//    ast: true,
//    debug: false,
//    hex: true,
//    stdout: false,
//    outputDir: out,
//    outputToFiles: false,
//    cmdPrefix: findCompiler(),
//    timeout: 7200000
//  }
//);
//
//if (result.errors.length > 0) {
//    console.log(`Compile contract ${filePath} failed: `, result.errors);
//    throw result.errors;
//}
//const InformationBounty = buildContractClass(result);

const desc = JSON.parse(fs.readFileSync(path.join(out, "bounty_desc.json")).toString());
const InformationBounty = buildContractClass(desc);

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
    "ew": ew,
    "Hew": [Hew0, Hew1],
    "Qa": [QaxArray, QayArray],
    "Qb": [QbxArray, QbyArray],
    "nonce": nonce,
};

fs.writeFileSync("input.json", JSON.stringify(witness));

output = execSync(`node test_main_js/generate_witness.js test_main_js/test_main.wasm input.json witness.wtns`).toString();
console.log(output);
output = execSync(`snarkjs groth16 prove circuit_0000.zkey witness.wtns proof.json public.json`).toString();
console.log(output);
let proof = JSON.parse(fs.readFileSync("proof.json").toString());
let publicSignals = JSON.parse(fs.readFileSync("public.json").toString());

let newLockingScript = buildPublicKeyHashScript(new Ripemd160(hash160(
    "04" + Qb.x.toString(16) + Qb.y.toString(16)
)));

let inputSatoshis = rewardSats;

let response: any = new SyncRequestClient().get(`https://api.whatsonchain.com/v1/bsv/${network}/tx/hash/${contractTxId}`);
let contractTxLs = bsv.Script(response.vout[contractTxOutIdx].scriptPubKey.hex);
let tx = new bsv.Transaction();

tx.addOutput(new bsv.Transaction.Output({
    script: newLockingScript,
    satoshis: rewardSats
}))

let dataOutScript = "006a" + "04" + Qb.x.toString(16) + Qb.y.toString(16) +
    bigIntToHexStrFixedLen(nonce, 64) + ewHex;

tx.addOutput(new bsv.Transaction.Output({
    script: dataOutScript,
    satoshis: 0
}))

let preimage = getPreimage(tx, infoBounty.lockingScript, inputSatoshis)
let uls = infoBounty.unlock(
    new ContractTypes.ECPoint({ x: QbxArray, y: QbyArray }),
    ew,
    new Sha256(Hew),
    nonce,
    proofToSCryptType(proof, ContractTypes),
    preimage
).unlockingScript;

tx.inputs
tx.addInput(new bsv.Transaction.Input({
    prevTxId: contractTxId,
    outputIndex: contractTxOutIdx,
    script: uls
}), contractTxLs, rewardSats);

response = new SyncRequestClient()
    .addHeader("Content-Type", "application/json")
    .addHeader("Authorization", taalAPIKey)
    .post("https://api.taal.com/api/v1/broadcast",
        { "rawTx": tx.toString() });
console.log(response);
