pragma circom 2.0.2;

include "ecdsa/ecdsa.circom";
include "ecdsa/secp256k1.circom";


// Circuit for proving the knowledge of the square root of a number.
// w * w = x
// ---------------
// `n`: chunk length in bits for a private key
// `k`: chunk count for a private key
template Main(n, k) {

    signal input w;
    signal input db[k];
    signal input Qa[2][k];
    signal input Qb[2][k];
    signal input Qs[2][k];
    signal input ew;
    signal input x;

    //// Assert w is a valid solution.
    x === w * w;

    //// Assert that (db * Qa) = Qs
    // n * k == 256
    assert(n * k >= 256);
    assert(n * (k-1) < 256);
    component privToPub0 = Secp256k1ScalarMult(n, k);
    for (var i = 0; i < k; i++) {
        privToPub0.scalar[i] <== db[i];
    }
    for (var i = 0; i < k; i++) {
        privToPub0.point[0][i] <== Qa[0][i];
        privToPub0.point[1][i] <== Qa[1][i];
    }

    signal Qs_x_diff[k];
    signal Qs_y_diff[k];
    for (var i = 0; i < k; i++) {
        Qs_x_diff[i] <-- privToPub0.out[0][i] - Qs[0][i];
        Qs_x_diff[i] === 0;
        Qs_y_diff[i] <-- privToPub0.out[1][i] - Qs[1][i];
        Qs_y_diff[i] === 0;
    }

    //// Assert that (db * G) = Qb
    component privToPub1 = ECDSAPrivToPub(n, k);
    for (var i = 0; i < k; i++) {
        privToPub1.privkey[i] <== db[i];
    }

    signal Qb_x_diff[k];
    signal Qb_y_diff[k];
    for (var i = 0; i < k; i++) {
        Qb_x_diff[i] <-- privToPub1.pubkey[0][i] - Qb[0][i];
        Qb_x_diff[i] === 0;
        Qb_y_diff[i] <-- privToPub1.pubkey[1][i] - Qb[1][i];
        Qb_y_diff[i] === 0;
    }

    //// Assert that encrypting w with Qs produces ew.
    // TODO: https://github.com/weijiekoh/poseidon-encryption-circom
    
}

