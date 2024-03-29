import { expect } from 'chai';
import path from 'path'

import { Point } from '@noble/secp256k1';
import { poseidonEncrypt, formatSharedKey } from './utils/poseidonEncryption';

import { bigIntToArray } from './utils/misc';

import * as circom_tester from 'circom_tester'
const wasm_tester = circom_tester.wasm;



describe("SharedKeyEncryption", function () {
    this.timeout(1000 * 1000 * 10);

    let m = [43, 32, 456432];

    let s: bigint = 90388020393783788847120091912026443124559466591761394939671630294477859800601n;
    let P: Point = Point.fromPrivateKey(s);

    let PxArray = bigIntToArray(64, 4, P.x);

    let nonce = BigInt(1234);

    let formatedSK: BigInt[];
    let em: BigInt[];
    let circuitFormatSharedKey: any;
    let circuitPoseidonEncrypt: any;

    before(async function () {
        // Calculate everything in JS. Assume these are correct.
        formatedSK = formatSharedKey(PxArray);
        em = poseidonEncrypt(m, formatedSK, nonce);
        circuitFormatSharedKey = await wasm_tester(path.join(__dirname, "circuits", "test_format_shared_key.circom"));
        circuitPoseidonEncrypt = await wasm_tester(path.join(__dirname, "circuits", "test_poseidon_encrypt.circom"));
    });

    it('Testing formating shared key in Circom',
        async function () {
            let witness = await circuitFormatSharedKey.calculateWitness(
                {
                    "pointX": PxArray
                });
            expect(witness[1]).to.equal(formatedSK[0]);
            expect(witness[2]).to.equal(formatedSK[1]);
            await circuitFormatSharedKey.checkConstraints(witness);
        }
    );

    it('Testing encryption with shared key in Circom',
        async function () {
            let witness = await circuitPoseidonEncrypt.calculateWitness(
                {
                    "ciphertext": em,
                    "message": m,
                    "nonce": nonce,
                    "key": formatedSK
                }
            );
            expect(witness[1]).to.equal(1n);
            await circuitPoseidonEncrypt.checkConstraints(witness);
        }
    );
});
