import { FixedArray } from "scrypt-ts";
import { BN256, BN256Pairing, G1Point, Proof, VerifyingKey } from "../../../src/contracts/snark";

function bigIntToArray(n: number, k: number, x: bigint) {
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

function bigIntToHexStrFixedLen(val: bigint, len: number): string {
    let partStr = val.toString(16);
    return "0".repeat(len - partStr.length) + partStr;
}

function vKeyToSCryptType(vKey: any): VerifyingKey {

    const alpha = BN256.createCurvePoint({
        x: BigInt(vKey.vk_alpha_1[0]),
        y: BigInt(vKey.vk_alpha_1[1])
    })

    const beta = BN256.createTwistPoint({
        x: {
            x: BigInt(vKey.vk_beta_2[0][0]),
            y: BigInt(vKey.vk_beta_2[0][1]),
        },
        y: {
            x: BigInt(vKey.vk_beta_2[1][0]),
            y: BigInt(vKey.vk_beta_2[1][1]),
        }
    })

    // Precalc:
    const millerb1a1 = BN256Pairing.miller(beta, alpha)

    const gamma = BN256.createTwistPoint({
        x: {
            x: BigInt(vKey.vk_gamma_2[0][0]),
            y: BigInt(vKey.vk_gamma_2[0][1]),
        },
        y: {
            x: BigInt(vKey.vk_gamma_2[1][0]),
            y: BigInt(vKey.vk_gamma_2[1][1]),
        }
    })

    const delta = BN256.createTwistPoint({
        x: {
            x: BigInt(vKey.vk_delta_2[0][0]),
            y: BigInt(vKey.vk_delta_2[0][1]),
        },
        y: {
            x: BigInt(vKey.vk_delta_2[1][0]),
            y: BigInt(vKey.vk_delta_2[1][1]),
        }
    })

    const gammaAbc: FixedArray<G1Point, 2> = [
        {
            x: BigInt(vKey.IC[0][0]),
            y: BigInt(vKey.IC[0][1]),
        },
        {
            x: BigInt(vKey.IC[1][0]),
            y: BigInt(vKey.IC[1][1]),
        }
    ]

    const vk: VerifyingKey = {
        millerb1a1: millerb1a1,
        gamma: gamma,
        delta: delta,
        gammaAbc: gammaAbc
    }

    return vk
}

function proofToSCryptType(proof: any): Proof {
    const res: Proof = {
        a: {
            x: BigInt(proof.pi_a[0]),
            y: BigInt(proof.pi_a[1]),
        },
        b: {
            x: {
                x: BigInt(proof.pi_b[0][0]),
                y: BigInt(proof.pi_b[0][1]),
            },
            y: {
                x: BigInt(proof.pi_b[1][0]),
                y: BigInt(proof.pi_b[1][1]),
            },
        },
        c: {
            x: BigInt(proof.pi_c[0]),
            y: BigInt(proof.pi_c[1])
        }
    }
    return res
}

export {
    bigIntToArray,
    bigIntToHexStrFixedLen,
    vKeyToSCryptType,
    proofToSCryptType
}
