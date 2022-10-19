import { expect } from 'chai';
import path = require("path");
const fs = require("fs");

import { Point } from '@noble/secp256k1';
import { poseidonEncrypt, formatSharedKey } from './util/poseidonEncryption';

import { bigIntToArray } from './util/misc';

const circom_tester = require('circom_tester');
const wasm_tester = circom_tester.wasm;



describe("MainCircuit", function () {
    this.timeout(1000 * 1000 * 10);
    
    let da: bigint = 88549154299169935420064281163296845505587953610183896504176354567359434168161n;
    let Qa: Point = Point.fromPrivateKey(da);
    let QaxArray = bigIntToArray(64, 4, Qa.x);
    let QayArray = bigIntToArray(64, 4, Qa.y);

    let w = BigInt(4);
    let x = BigInt(16);  // 4 * 4 = 16
    
    let db: bigint = 90388020393783788847120091912026443124559466591761394939671630294477859800601n;
    let Qb: Point = Point.fromPrivateKey(db);

    let Qs: Point = Qb.multiply(da);
    
    let dbArray = bigIntToArray(64, 4, db);
    let QbxArray = bigIntToArray(64, 4, Qb.x);
    let QbyArray = bigIntToArray(64, 4, Qb.y);
    let QsxArray = bigIntToArray(64, 4, Qs.x);
    let QsyArray = bigIntToArray(64, 4, Qs.y);

    let nonce = BigInt(1234);
    let ew = poseidonEncrypt([w], formatSharedKey(QsxArray), nonce);
    
    let circuit: any;
    
    before(async function () {
        circuit = await wasm_tester(path.join(__dirname, "circuits", "test_main_allpublic.circom"));
    });
    
    it('Testing main circuit', 
        async function() { 
            let witness = await circuit.calculateWitness(
                {
                    "w": w, 
                    "db": dbArray,
                    "Qs": [QsxArray, QsyArray],
                    "Qa": [QaxArray, QayArray],
                    "Qb": [QbxArray, QbyArray],
                    "nonce": nonce,
                    "ew": ew,
                    "x": x
                }
            );
            await circuit.checkConstraints(witness);
        }
    );

});
