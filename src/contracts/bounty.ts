import {
    assert,
    ByteString,
    FixedArray,
    hash160,
    hash256,
    method,
    prop,
    PubKey,
    reverseByteString,
    sha256,
    Sha256,
    Sig,
    SigHash,
    SmartContract,
    toByteString,
    Utils,
} from 'scrypt-ts'
import { unpack } from 'scryptlib/dist/builtins'
import { Proof, SNARK, VerifyingKey } from './snark'

// Point coordinates on secp256k1 are repesentat as 4 field elements
// inside our Circom code. That's why we use 4 integers here.
type ECPoint = {
    x: FixedArray<bigint, 4>
    y: FixedArray<bigint, 4>
}

export class SudokuBounty extends SmartContract {

    @prop()
    Qa: ECPoint        // Buyers (Alice) public key.

    @prop()
    vk: VerifyingKey   // Verifying key from the circuits setup.

    @prop()
    satsReward: bigint // Amount of satoshis to be handed as a reward for the solution.

    @prop()
    expirationBlockN: bigint // nLocktime of deadline when Alice can reclaim the reward.
    // Can be timestamp or block height but in our case we use block height.
    // (see deadline() public function)


    constructor(
        Qa: ECPoint,
        vk: VerifyingKey,
        satsReward: bigint,
        expirationBlockN: bigint
    ) {
        super(...arguments)
        this.Qa = Qa
        this.vk = vk
        this.satsReward = satsReward
        this.expirationBlockN = expirationBlockN
    }

    @method(SigHash.ANYONECANPAY_ALL)
    public unlock(
        Qb: ECPoint,                   // Bobs public key.
        ew: FixedArray<bigint, 82>,    // Solution of puzzle, encrypted with shared key k.
        Hpub: Sha256,                  // Hash of public inputs.
        nonce: bigint,                 // Nonce for encryption with shared key. Can be timestamp.
        pi: Proof,                     // Proof of solution for the whole circuit C.
    ) {
        //// Concatinate the public inputs to the circuit as a byte array and hash them. //////////////////
        // Compare the result with the hash value passed by Bob.
        // This ensures the seller included the correct public inputs.
        let pubInputBytes = toByteString('')
        pubInputBytes += SudokuBounty.point2PubKey(this.Qa).slice(2)
        pubInputBytes += SudokuBounty.point2PubKey(Qb).slice(2)
        pubInputBytes += SudokuBounty.toBEUnsigned32(nonce)
        for (let i = 0; i < 82; i++) {
            pubInputBytes += SudokuBounty.toBEUnsigned32(ew[i])
        }
        assert(sha256(pubInputBytes) == Hpub, 'pubInputBytes hash mismatch')

        //// Verify the proof. ////////////////////////////////////////////////////////////////////////////
        // As we can see, the only actual real public input to the circuit is the hash of the supposed 
        // public inputs.
        // This is done soley to reduce the size of the verifier as each additional public input value would
        // add a EC scalar multiplication to the script.
        const pubInputs: FixedArray<bigint, 2> = [
            unpack(reverseByteString(Hpub.slice(0, 32), 32) + toByteString('00')),  // Hpub is BE by default, hence the reverseBytes.
            unpack(reverseByteString(Hpub.slice(32), 32) + toByteString('00'))
        ]

        const proofCorrect = SNARK.verify(this.vk, pubInputs, pi)
        assert(proofCorrect, 'Invalid proof')

        //// Ensure next output will pay Qb. //////////////////////////////////////////////////////////////
        const address = hash160(SudokuBounty.point2PubKey(Qb))
        const out0 = Utils.buildPublicKeyHashOutput(address, this.satsReward)

        // Ensure the seller adds another output with just OP_FLASE + OP_RETURN + Qb + nonce + ew
        // to make it easier for the buyer to parse the values.
        const out1Script: ByteString = toByteString('006a') + pubInputBytes;
        const out1 = Utils.buildOutput(out1Script, 0n);

        // Add change output.
        const out2 = this.buildChangeOutput()

        assert(hash256(out0 + out1 + out2) == this.ctx.hashOutputs, 'hashOutputs mismatch')
    }

    @method()
    static point2PubKey(point: ECPoint): PubKey {
        // Convert a point to a uncompressed public key. Coordinates are encoded as BE values.
        // point.x[0] are the least significant bytes (also in BE format),
        // point.x[3] are the most significant bytes (also in BE format)
        return PubKey(toByteString('04') +
            SudokuBounty.toBEUnsigned8(point.x[3]) +
            SudokuBounty.toBEUnsigned8(point.x[2]) +
            SudokuBounty.toBEUnsigned8(point.x[1]) +
            SudokuBounty.toBEUnsigned8(point.x[0]) +
            SudokuBounty.toBEUnsigned8(point.x[3]) +
            SudokuBounty.toBEUnsigned8(point.x[2]) +
            SudokuBounty.toBEUnsigned8(point.x[1]) +
            SudokuBounty.toBEUnsigned8(point.x[0])
        )
    }

    @method()
    public deadline(sig: Sig) {
        // Check if signature by Qa.
        assert(this.checkSig(sig, SudokuBounty.point2PubKey(this.Qa)))

        // Ensure the unlocking TX actually has a valid nLocktime and nSequence.
        assert(this.ctx.sequence < 4294967295n, // Lower than UINT_MAX. Check https://wiki.bitcoinsv.io/index.php/NLocktime_and_nSequence
            'nSequence not lower than UINT_MAX')
        assert(this.ctx.locktime >= this.expirationBlockN &&
            this.ctx.locktime < 500000000n,
            'nLocktime out of range');
    }

    @method()
    static toBEUnsigned8(n: bigint): PubKey {
        const m = Utils.toLEUnsigned(n, 8n);
        return PubKey(reverseByteString(m, 8));
    }

    @method()
    static toBEUnsigned32(n: bigint): PubKey {
        const m = Utils.toLEUnsigned(n, 32n);
        return PubKey(reverseByteString(m, 32));
    }
}
