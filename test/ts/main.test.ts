import path = require("path");
const fs = require("fs");

import { Point } from '@noble/secp256k1';
import { poseidonEncrypt, formatSharedKey } from './util/poseidonEncryption';


import { sha256 } from "scryptlib";

import { bigIntToArray } from './util/misc';

const circom_tester = require('circom_tester');
const wasm_tester = circom_tester.wasm;



describe("MainCircuit", function () {
    this.timeout(1000 * 1000 * 10);

    let da: bigint = 88549154299169935420064281163296845505587953610183896504176354567359434168161n;
    let Qa: Point = Point.fromPrivateKey(da);
    let QaxArray = bigIntToArray(64, 4, Qa.x);
    let QayArray = bigIntToArray(64, 4, Qa.y);

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

    let nonce = BigInt(1234);
    let ew = poseidonEncrypt(wFlattened, formatSharedKey(QsxArray), nonce);

    let ewHex = '';
    for (var i = 0; i < ew.length; i++) {
        let partStr = ew[i].toString(16);
        ewHex += "0".repeat(64 - partStr.length) + partStr;
    }
    let Hew = sha256(ewHex);
    let Hew0 = BigInt('0x' + Hew.substring(0, 32));
    let Hew1 = BigInt('0x' + Hew.substring(32, 64));

    let circuit: any;

    before(async function () {
        circuit = await wasm_tester(path.join(__dirname, "circuits", "test_main_allpublic.circom"));
    });

    it('Testing main circuit',
        async function () {
            let witness = await circuit.calculateWitness(
                {
                    "w": w,
                    "db": dbArray,
                    "Qs": [QsxArray, QsyArray],
                    "ew": ew,
                    "Hew": [Hew0, Hew1],
                    "Qa": [QaxArray, QayArray],
                    "Qb": [QbxArray, QbyArray],
                    "nonce": nonce,
                }
            );
            await circuit.checkConstraints(witness);
        }
    );

});
