import { expect, use } from 'chai'
import chaiAsPromised from 'chai-as-promised'
use(chaiAsPromised)

import path from 'path'
import { readFileSync, writeFileSync } from 'fs'
import * as snarkjs from 'snarkjs'


import { execSync } from 'child_process'

import { Point } from '@noble/secp256k1'
import { poseidonEncrypt, formatSharedKey, poseidonDecrypt } from './utils/poseidonEncryption'

import { bigIntToArray, proofToSCryptType, vKeyToSCryptType } from './utils/misc'
import { bsv, findSig, hash160, MethodCallOptions, Sha256, sha256, Utils } from 'scrypt-ts'
import { SudokuBounty } from '../../src/contracts/bounty'
import { getDummySigner, getDummyUTXO } from './utils/txHelper'
import { myPublicKey } from '../utils/privateKey'


// This file test the full end-to-end process of an information bounty as described by the patent.

const da: bigint = 88549154299169935420064281163296845505587953610183896504176354567359434168161n
const Qa: Point = Point.fromPrivateKey(da)
const QaxArray = bigIntToArray(64, 4, Qa.x)
const QayArray = bigIntToArray(64, 4, Qa.y)
const rewardSats = 10000n
const contractExpireBlock = 761406n

describe("End2End", function () {
    this.timeout(1000 * 1000 * 10)

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
    ]
    let wFlattened = w.reduce((accumulator: any, value: any) => accumulator.concat(value), [])

    let db: bigint = 90388020393783788847120091912026443124559466591761394939671630294477859800601n
    let Qb: Point = Point.fromPrivateKey(db)

    let Qs: Point = Qb.multiply(da)

    let dbArray = bigIntToArray(64, 4, db)
    let QbxArray = bigIntToArray(64, 4, Qb.x)
    let QbyArray = bigIntToArray(64, 4, Qb.y)
    let QsxArray = bigIntToArray(64, 4, Qs.x)
    let QsyArray = bigIntToArray(64, 4, Qs.y)

    let nonce = BigInt(1234) // TODO
    let ew = poseidonEncrypt(wFlattened, formatSharedKey(QsxArray), nonce)

    let QaHex = Qa.toHex(false).slice(2)  // Slice away "04" at the beggining from uncompressed encoding.
    let QbHex = Qb.toHex(false).slice(2)

    let nonceHex = nonce.toString(16)
    nonceHex = "0".repeat(64 - nonceHex.length) + nonceHex

    let ewHex = ''
    for (let i = 0; i < ew.length; i++) {
        let partStr = ew[i].toString(16)
        ewHex += "0".repeat(64 - partStr.length) + partStr
    }
    let pubInputsHex = QaHex + QbHex + nonceHex + ewHex
    let Hpub = sha256(pubInputsHex)
    let Hpub0 = BigInt('0x' + Hpub.substring(0, 32))
    let Hpub1 = BigInt('0x' + Hpub.substring(32, 64))

    let infoBounty: any
    let vKey: any
    let ContractTypes: any

    let witness: any
    let proof: any
    let publicSignals: any

    before(async function () {
        // TODO: Don't write these files to the root dir. Cd into some tmp dir or something.

        // Compile circuit.
        let circuitPath = path.join(__dirname, 'circuits', 'test_main.circom')
        let output = execSync(`circom ${circuitPath} --r1cs --wasm --sym`).toString()
        console.log(output)

        output = execSync(`snarkjs groth16 setup test_main.r1cs pot22_final.ptau circuit_0000.zkey`).toString()
        console.log(output)

        // IMPORTANT: When using Groth16 in production you need a phase 2 contribution here:
        // https://github.com/iden3/snarkjs#groth16

        output = execSync(`snarkjs zkey export verificationkey circuit_0000.zkey verification_key.json`).toString()
        console.log(output)

        vKey = JSON.parse(readFileSync("verification_key.json").toString())

        // Generate proof.
        witness = {
            "w": w,
            "db": dbArray,
            "Qs": [QsxArray, QsyArray],
            "Qa": [QaxArray, QayArray],
            "Qb": [QbxArray, QbyArray],
            "nonce": nonce,
            "ew": ew,
            "Hpub": [Hpub0, Hpub1]
        }

        writeFileSync("input.json", JSON.stringify(witness))

        output = execSync(`node test_main_js/generate_witness.js test_main_js/test_main.wasm input.json witness.wtns`).toString()
        console.log(output)
        output = execSync(`snarkjs groth16 prove circuit_0000.zkey witness.wtns proof.json public.json`).toString()
        console.log(output)
        proof = JSON.parse(readFileSync("proof.json").toString())
        publicSignals = JSON.parse(readFileSync("public.json").toString())

        // Compile sCrypt conract.
        await SudokuBounty.compile()

        infoBounty = new SudokuBounty(
            new ContractTypes.ECPoint({ x: QaxArray, y: QayArray }),
            vKeyToSCryptType(vKey),
            rewardSats,
            contractExpireBlock
        )
        infoBounty.connect(getDummySigner())

    })

    it('Testing proof verification with snarkjs',
        async function () {
            // Verify proof in js.
            let res = await snarkjs.groth16.verify(vKey, publicSignals, proof)
            expect(res).to.be.true
        }
    )

    it('Testing proof verification with sCrypt',
        async function () {
            // Verify proof using sCrypt
            infoBounty.bindTxBuilder("unlock", (current: SudokuBounty, options: MethodCallOptions<SudokuBounty>, ...args: any) => {
                const newLockingScript = Utils.buildPublicKeyHashScript(hash160(
                    "04" + Qb.x.toString(16) + Qb.y.toString(16)
                ))
                let dataOutScript = "006a" + pubInputsHex

                const unsignedTx: bsv.Transaction = new bsv.Transaction()
                    .addInput(current.buildContractInput(options.fromUTXO))
                    // add a p2pkh output
                    .addOutput(new bsv.Transaction.Output({
                        script: bsv.Script.fromHex(newLockingScript),
                        satoshis: Number(rewardSats)
                    }))
                    // data output
                    .addOutput(new bsv.Transaction.Output({
                        script: bsv.Script.fromHex(dataOutScript),
                        satoshis: 0
                    }))
                    // add change output
                    .change(options.changeAddress)

                return Promise.resolve({
                    tx: unsignedTx,
                    atInputIndex: 0, // the contract input's index
                    nexts: []
                })
            })
            const { tx: callTx, atInputIndex } = await infoBounty.methods.unlock(
                new ContractTypes.ECPoint({ x: QbxArray, y: QbyArray }),
                ew,
                Sha256(Hpub),
                nonce,
                proofToSCryptType(proof),
                // method call options:
                {
                    fromUTXO: getDummyUTXO(),
                    pubKeyOrAddrToSign: myPublicKey,
                } as MethodCallOptions<SudokuBounty>
            )

            const result = callTx.verifyScript(atInputIndex)
            expect(result.success, result.error).to.eq(true)
        }
    )

    it('Testing parsing and decrypting solution',
        async function () {
            let _QbHex = pubInputsHex.slice(128, 256)
            let _nonceHex = pubInputsHex.slice(256, 320)
            let _ewHex = pubInputsHex.slice(320)

            let _Qb = new Point(
                BigInt("0x" + _QbHex.slice(0, 64)),
                BigInt("0x" + _QbHex.slice(64))
            )
            let _Qs: Point = _Qb.multiply(da)
            let _k = formatSharedKey(bigIntToArray(64, 4, Qs.x))

            let _nonce = BigInt("0x" + _nonceHex)

            let ewLen = _ewHex.length / 128
            let _ew: BigInt[] = []
            for (let i = 0; i < ewLen; i++) {
                _ew.push(BigInt("0x" + _ewHex.slice(i * 128, i * 128 + 128)))
            }

            let _wFlattened = poseidonDecrypt(_ew, _k, _nonce, ewLen)
            expect(_wFlattened).to.equal(wFlattened)
        }
    )

    it('Testing contracts deadline function',
        async function () {
            //// Should succeed if correct nLockTime.
            infoBounty.bindTxBuilder("deadline", (current: SudokuBounty, options: MethodCallOptions<SudokuBounty>, ...args: any) => {
                const unsignedTx: bsv.Transaction = new bsv.Transaction()
                    .addInput(current.buildContractInput(options.fromUTXO))
                    .change(options.changeAddress)

                unsignedTx.nLockTime = Number(contractExpireBlock) // Should be >= contractExpireBlock
                unsignedTx.inputs[0].sequenceNumber = 0 // nSequence needs to be lower than UINT_MAX

                return Promise.resolve({
                    tx: unsignedTx,
                    atInputIndex: 0, // the contract input's index
                    nexts: []
                })
            })

            const { tx: callTx, atInputIndex } = await infoBounty.methods.deadline(
                (sigResp) => findSig(sigResp, myPublicKey),
                // method call options:
                {
                    fromUTXO: getDummyUTXO(),
                    pubKeyOrAddrToSign: myPublicKey,
                } as MethodCallOptions<SudokuBounty>
            )

            const result = callTx.verifyScript(atInputIndex)
            expect(result.success, result.error).to.eq(true)

            //// Should fail if nLockTime too low.
            infoBounty.bindTxBuilder("deadline", (current: SudokuBounty, options: MethodCallOptions<SudokuBounty>, ...args: any) => {
                const unsignedTx: bsv.Transaction = new bsv.Transaction()
                    .addInput(current.buildContractInput(options.fromUTXO))
                    .change(options.changeAddress)

                unsignedTx.nLockTime = Number(contractExpireBlock) - 1
                unsignedTx.inputs[0].sequenceNumber = 0

                return Promise.resolve({
                    tx: unsignedTx,
                    atInputIndex: 0, // the contract input's index
                    nexts: []
                })
            })

            expect(
                infoBounty.methods.deadline(
                    (sigResp) => findSig(sigResp, myPublicKey),
                    // method call options:
                    {
                        fromUTXO: getDummyUTXO(),
                        pubKeyOrAddrToSign: myPublicKey,
                    } as MethodCallOptions<SudokuBounty>
                )
            ).to.be.rejectedWith(/nLocktime out of range/)
        }
    )

})
