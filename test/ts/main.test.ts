import { expect } from 'chai';
import path = require("path");
const fs = require("fs");
import {execSync, ChildProcess } from 'child_process';


import { buildContractClass, VerifyResult, compileContract, buildTypeClasses } from "scryptlib";
const snarkjs = require('snarkjs');

import { Point } from '@noble/secp256k1';
const circom_tester = require('circom_tester');
const wasm_tester = circom_tester.wasm;


function bigint_to_array(n: number, k: number, x: bigint) {
    let mod: bigint = 1n;
    for (var idx = 0; idx < n; idx++) {
        mod = mod * 2n;
    }

    let ret: bigint[] = [];
    var x_temp: bigint = x;
    for (var idx = 0; idx < k; idx++) {
        ret.push(x_temp % mod);
        x_temp = x_temp / mod;
    }
    return ret;
}

const da: bigint = 88549154299169935420064281163296845505587953610183896504176354567359434168161n;
const Qa: Point = Point.fromPrivateKey(da);

describe("MainCircuit", function () {
    this.timeout(1000 * 1000 * 10);
    
    let w = 4;
    let x = 16;  // 4 * 4 = 16
    
    let db: bigint = 90388020393783788847120091912026443124559466591761394939671630294477859800601n;
    let Qb: Point = Point.fromPrivateKey(db);
    let Qs: Point = Qb.multiply(db);
    
    let ew = 0;  // TODO: use Poseidon encryption
    
    let dbArray = bigint_to_array(64, 4, db);
    let QbxArray = bigint_to_array(64, 4, Qb.x);
    let QbyArray = bigint_to_array(64, 4, Qb.y);
    let QsxArray = bigint_to_array(64, 4, Qs.x);
    let QsyArray = bigint_to_array(64, 4, Qs.y);
    
    let infoBounty: any;
    let vKey: any;
    let ContractTypes: any;

    before(async function () {
        // TODO: Don't write these files to the root dir. Cd into some tmp dir or something.

        // Compile circuit.
        let circuitPath = path.join(__dirname, 'circuits', 'test_main.circom');
        let output = execSync(`circom ${circuitPath} --r1cs --wasm --sym`).toString();
        console.log(output);
        
        // Perform setup to produce VK, PK.
        output = execSync(`snarkjs groth16 setup test_main.r1cs pot21_final.ptau circuit_0000.zkey`).toString();
        console.log(output);
        
        // IMPORTANT: When using Groth16 in production you need a phase 2 contribution here:
        // https://github.com/iden3/snarkjs#groth16
        
        output = execSync(`snarkjs zkey export verificationkey circuit_0000.zkey verification_key.json`).toString();
        console.log(output);
        
        vKey = JSON.parse(fs.readFileSync("verification_key.json"));

        // Compile sCrypt conract.
        let filePath = path.join(__dirname, '..', '..', 'contracts', 'bounty.scrypt');
        let out = path.join(__dirname, '..', '..', 'out-scrypt');

        let result = compileContract(filePath, { out: out });

        if (result.errors.length > 0) {
            console.log(`Compile contract ${filePath} failed: `, result.errors);
            throw result.errors;
        }
        const InformationBounty = buildContractClass(result);
        ContractTypes = buildTypeClasses(InformationBounty);
        infoBounty = new InformationBounty(todo);
    });
    
    // Compute witness and check constraints.
    it('Testing Main ', 
        async function() { 
            let witness = {
                    "w": w, 
                    "db": dbArray,
                    "Qs": [QsxArray, QsyArray],
                    "Qb": [QbxArray, QbyArray],
                    "nonce": 1234567890,
                    "ew": ew,
                    "x": x
            };
            
            // Generate proof.
            let { proof, publicSignals } = snarkjs.groth16.fullProve(witness, "test_main_js/test_main.wasm", "circuit_0000.zkey");
            console.log(proof);

            // Verify proof in js.
            let res = await snarkjs.groth16.verify(vKey, publicSignals, proof);
            expect(res).to.be.true;

            // Verify proof in sCrypt / Bitcoin script.
            const result = infoBounty.unlock(todo).verify()
            expect(result.success, result.error).to.be.true;
        }
    );
        
});
