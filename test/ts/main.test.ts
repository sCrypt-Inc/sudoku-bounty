import path = require("path");

import { buildContractClass, VerifyResult, compileContract } from "scryptlib";

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
    this.timeout(1000 * 1000);
    
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
    
    // Runs Circom compilation.
    let circuit: any;
    before(async function () {
        circuit = await wasm_tester(path.join(__dirname, "circuits", "test_main.circom"));
    });
    
    // Compute witness and check constraints.
    it('Testing Main ', async function() { 
            let witness = await circuit.calculateWitness(
                {
                    "w": w, 
                    "db": dbArray,
                    "Qb": [QbxArray, QbyArray],
                    "Qs": [QsxArray, QsyArray],
                    "ew": ew,
                    "x": x
                }
            );
            await circuit.checkConstraints(witness);
        });
        
    // Perform setup.

    // Generate proof.

    // Verify proof in js.

    // Verify proof in sCrypt / Bitcoin script.
    
    
    let infoBounty: any
    let result: VerifyResult

    before(() => {
        let filePath = path.join(__dirname, '..', '..', 'contracts', 'bounty.scrypt')
        let out = path.join(__dirname, '..', '..', 'out-scrypt')

        let result = compileContract(filePath, { out: out });

        if (result.errors.length > 0) {
            console.log(`Compile contract ${filePath} failed: `, result.errors)
            throw result.errors;
        }
        const InformationBounty = buildContractClass(result);
        infoBounty = new InformationBounty();
    });

});
