import { expect } from 'chai';
import path = require("path");
const fs = require("fs");
const crypto = require("crypto");
import {execSync, ChildProcess } from 'child_process';


import { buildContractClass, VerifyResult, compileContract, buildTypeClasses,
         ScryptType, hash160, PubKey, Ripemd160, bsv, getPreimage,
         buildPublicKeyHashScript, signTx} from "scryptlib";
const snarkjs = require('snarkjs');

import { Point } from '@noble/secp256k1';
import { poseidonEncrypt, formatSharedKey, EcdhSharedKey } from './util/poseidonEncryption';

import { bigIntToArray, vKeyToSCryptType, proofToSCryptType } from './util/misc';


// This file test the full end-to-end process of an information bounty as described by the patent.

const da: bigint = 88549154299169935420064281163296845505587953610183896504176354567359434168161n;
const Qa: Point = Point.fromPrivateKey(da);
const QaxArray = bigIntToArray(64, 4, Qa.x);
const QayArray = bigIntToArray(64, 4, Qa.y);

describe("End2End", function () {
    this.timeout(1000 * 1000 * 10);
    
    let rewardSats = 10000;
    let contractExpireBlock = 761406;

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
    let unsolved = [
        [0, 0, 0, 0, 0, 6, 0, 0, 0],
        [0, 0, 7, 2, 0, 0, 8, 0, 0],
        [9, 0, 6, 8, 0, 0, 0, 1, 0],
        [3, 0, 0, 7, 0, 0, 0, 2, 9],
        [0, 0, 0, 0, 0, 0, 0, 0, 0],
        [4, 0, 0, 5, 0, 0, 0, 7, 0],
        [6, 5, 0, 1, 0, 0, 0, 0, 0],
        [8, 0, 1, 0, 5, 0, 3, 0, 0],
        [7, 9, 2, 0, 0, 0, 0, 0, 4],
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

    let nonce = BigInt(1234); // TODO
    let ew = poseidonEncrypt(wFlattened, formatSharedKey(QsxArray), nonce);
    
    let infoBounty: any;
    let vKey: any;
    let ContractTypes: any;
    
    let witness: any;
    let proof: any;
    let publicSignals: any;

    before(async function () {
        // TODO: Don't write these files to the root dir. Cd into some tmp dir or something.

        // Compile circuit.
        let circuitPath = path.join(__dirname, 'circuits', 'test_main.circom');
        let output = execSync(`circom ${circuitPath} --r1cs --wasm --sym`).toString();
        console.log(output);

        output = execSync(`snarkjs groth16 setup test_main.r1cs pot21_final.ptau circuit_0000.zkey`).toString();
        console.log(output);
        
        // IMPORTANT: When using Groth16 in production you need a phase 2 contribution here:
        // https://github.com/iden3/snarkjs#groth16
        
        output = execSync(`snarkjs zkey export verificationkey circuit_0000.zkey verification_key.json`).toString();
        console.log(output);
        
        vKey = JSON.parse(fs.readFileSync("verification_key.json"));

        // Generate proof.
        
        witness = {
            "w": w, 
            "db": dbArray,
            "Qs": [QsxArray, QsyArray],
            "unsolved": unsolved,
            "Qa": [QaxArray, QayArray],
            "Qb": [QbxArray, QbyArray],
            "nonce": nonce,
            "ew": ew
        };

        fs.writeFile("input.json", JSON.stringify(witness), function(err:any) {
            if (err) {
                console.log(err);
            }
        });
        
        output = execSync(`node test_main_js/generate_witness.js test_main_js/circuit.wasm input.json witness.wtns`).toString();
        console.log(output);
        output = execSync(`snarkjs groth16 prove circuit_0000.zkey witness.wtns proof.json public.json`).toString();
        console.log(output);
        proof = JSON.parse(fs.readFileSync("proof.json").toString());
        publicSignals = JSON.parse(fs.readFileSync("public.json").toString());

        // Compile sCrypt conract.
        let filePath = path.join(__dirname, '..', '..', 'contracts', 'bounty.scrypt');
        let out = path.join(__dirname, '..', '..', 'out-scrypt');

        let result = compileContract(filePath, { out: out, desc: true });
        if (result.errors.length > 0) {
            console.log(`Compile contract ${filePath} failed: `, result.errors);
            throw result.errors;
        }
        const InformationBounty = buildContractClass(result);
        
        //const desc = JSON.parse(fs.readFileSync(path.join(out, "bounty_desc.json")).toString());
        //const InformationBounty = buildContractClass(desc);

        ContractTypes = buildTypeClasses(InformationBounty);

        infoBounty = new InformationBounty(
            new ContractTypes.ECPoint({ x: QaxArray, y: QayArray }),
            wFlattened,
            vKeyToSCryptType(vKey, ContractTypes),
            rewardSats,
            contractExpireBlock 
        );
        
    });
    
    it('Testing proof verification with snarkjs', 
        async function() { 
            // Verify proof in js.
            let res = await snarkjs.groth16.verify(vKey, publicSignals, proof);
            expect(res).to.be.true;
        }
    );

    it('Testing proof verification with sCrypt', 
        async function() { 
            // Verify proof in sCrypt / Bitcoin script.
            
            let newLockingScript = buildPublicKeyHashScript(new Ripemd160(hash160(
                "04" + Qb.x.toString(16) + Qb.y.toString(16)
            )));

            let inputSatoshis = rewardSats + 10000;
            let utxo = {
              txId: crypto.randomBytes(32).toString('hex'),
              outputIndex: 0,
              script: infoBounty.lockingScript,
              satoshis: inputSatoshis
            };
            let tx = new bsv.Transaction().from(utxo);

            tx.addOutput(new bsv.Transaction.Output({
              script: newLockingScript,
              satoshis: rewardSats
            }))

            let preimage = getPreimage(tx, infoBounty.lockingScript, inputSatoshis)

            let context = { tx, inputIndex: 0, inputSatoshis };
            const result = infoBounty.unlock(
                new ContractTypes.ECPoint({ x: QbxArray, y: QbyArray }),
                ew,
                nonce,
                proofToSCryptType(proof, ContractTypes),
                preimage
            ).verify(context);
            expect(result.success, result.error).to.be.true;
        }
    );

    it('Testing contracts deadline function', 
        async function() { 
            let inputSatoshis = rewardSats + 10000;
            let utxo = {
              txId: crypto.randomBytes(32).toString('hex'),
              outputIndex: 0,
              script: infoBounty.lockingScript,
              satoshis: inputSatoshis
            };
            let tx = new bsv.Transaction().from(utxo);
            
            // Should succeed if correct nLockTime.
            tx.nLockTime = contractExpireBlock; // Should be >= contractExpireBlock
            tx.inputs[0].sequenceNumber = 0;    // nSequence needs to be lower than UINT_MAX
            
            let preimage = getPreimage(tx, infoBounty.lockingScript, inputSatoshis)
            let sig = signTx(tx, new bsv.PrivateKey(da.toString(16), "testnet"), infoBounty.lockingScript, inputSatoshis)

            let context = { tx, inputIndex: 0, inputSatoshis };
            let result = infoBounty.deadline(sig, preimage).verify(context);
            expect(result.success, result.error).to.be.true;
            
            // Should should fail if nLockTime too low.
            tx.nLockTime = contractExpireBlock - 1; // Should be >= contractExpireBlock

            preimage = getPreimage(tx, infoBounty.lockingScript, inputSatoshis)
            sig = signTx(tx, new bsv.PrivateKey(da.toString(16), "testnet"), infoBounty.lockingScript, inputSatoshis)

            context = { tx, inputIndex: 0, inputSatoshis };
            result = infoBounty.deadline(sig, preimage).verify(context);
            expect(result.success, result.error).to.be.false;
        }
    );
        
});
