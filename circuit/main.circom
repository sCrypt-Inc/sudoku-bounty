pragma circom 2.0.2;

include "ecdsa/ecdsa.circom";
include "ecdsa/secp256k1.circom";
include "util/poseidon.circom";
include "sudoku/sudoku.circom";

// TODO: Move other templates than the main one under util/.

template BitArr2Num(n) {
    // Assume BE input.
    assert (n > 0);

    signal input in[n];
    signal output out;

    var sum = 0;
    for (var i = 0; i < n; i++) {
      assert (in[i] == 0 || in[i] == 1);
      sum += 2 ** i * in[n - 1 - i];
    }

    out <== sum;
}

template ConcatBitArr() {
    signal input b0[64];
    signal input b1[64];
    signal output out[128];
    
    for (var j = 0; j < 64; j++) {
        out[j] <== b0[j];
    }
    for (var j = 0; j < 64; j++) {
        out[j + 64] <== b1[j];
    }
}

template FromatSharedKey() {
    signal input pointX[4];
    signal output ks[2];
    
    component bits0 = Num2Bits(64);
    component bits1 = Num2Bits(64);
    component bits2 = Num2Bits(64);
    component bits3 = Num2Bits(64);
    
    bits0.in <== pointX[0];
    bits1.in <== pointX[1];
    bits2.in <== pointX[2];
    bits3.in <== pointX[3];
    
    component bitsKs0 = ConcatBitArr();
    component bitsKs1 = ConcatBitArr();
    
    for (var i = 0; i < 64; i++) {
        bitsKs0.b0[i] <== bits0.out[63 - i];
    }
    for (var i = 0; i < 64; i++) {
        bitsKs0.b1[i] <== bits1.out[63 - i];
    }
    for (var i = 0; i < 64; i++) {
        bitsKs1.b0[i] <== bits2.out[63 - i];
    }
    for (var i = 0; i < 64; i++) {
        bitsKs1.b1[i] <== bits3.out[63 - i];
    }
    
    component numKs0 = BitArr2Num(128);
    component numKs1 = BitArr2Num(128);
    
    for (var i = 0; i < 128; i++) {
        numKs0.in[i] <== bitsKs0.out[i];
    }
    for (var i = 0; i < 128; i++) {
        numKs1.in[i] <== bitsKs1.out[i];
    }

    ks[0] <== numKs0.out;
    ks[1] <== numKs1.out;
}

// Circuit for proving the knowledge of the solution to a sudoku puzzle.
// Secp256k1 256-bit values are representet as 4 x 64-bit values.
// ---------------
// `N`:           sudoku puzzle dimension
// `sqrtN`:       sqrt(sudoku puzzle dimension)
// `lCyphertext`: length of encrypted msg (see PoseidonEncryptCheck implementation)
template Main(N, sqrtN, lCyphertext) {

    // Private inputs:
    signal input w[N][N];           // Solition to the specified puzzle.
    signal input db[4];             // Seller (Bob) private key.
    signal input Qs[2][4];          // Shared (symmetric) key. Used to encrypt w.

    // Public inputs:
    signal input unsolved[N][N];    // Unsolved sudoku board.
    signal input Qa[2][4];          // Buyer (Alice) public key.
    signal input Qb[2][4];          // Seller (Bob) public key.
    signal input nonce;             // Needed to encrypt/decrypt xy.
    signal input ew[lCyphertext];   // Encrypted solution to puzzle.

    //// Assert w is a valid solution.
    component sudokuVerify = Sudoku(sqrtN, N);
    for (var i = 0; i < N; i++) {
        for (var j = 0; j < N; j++) {
            sudokuVerify.unsolved[i][j] <== unsolved[i][j];
            sudokuVerify.solved[i][j] <== w[i][j];
        }
    }

    //// Assert that (db * Qa) = Qs
    component privToPub0 = Secp256k1ScalarMult(64, 4);
    for (var i = 0; i < 4; i++) {
        privToPub0.scalar[i] <== db[i];
    }
    for (var i = 0; i < 4; i++) {
        privToPub0.point[0][i] <== Qa[0][i];
        privToPub0.point[1][i] <== Qa[1][i];
    }

    signal Qs_x_diff[4];
    signal Qs_y_diff[4];
    for (var i = 0; i < 4; i++) {
        Qs_x_diff[i] <-- privToPub0.out[0][i] - Qs[0][i];
        Qs_x_diff[i] === 0;
        Qs_y_diff[i] <-- privToPub0.out[1][i] - Qs[1][i];
        Qs_y_diff[i] === 0;
    }

    //// Assert that (db * G) = Qb
    component privToPub1 = ECDSAPrivToPub(64, 4);
    for (var i = 0; i < 4; i++) {
        privToPub1.privkey[i] <== db[i];
    }

    signal Qb_x_diff[4];
    signal Qb_y_diff[4];
    for (var i = 0; i < 4; i++) {
        Qb_x_diff[i] <-- privToPub1.pubkey[0][i] - Qb[0][i];
        Qb_x_diff[i] === 0;
        Qb_y_diff[i] <-- privToPub1.pubkey[1][i] - Qb[1][i];
        Qb_y_diff[i] === 0;
    }

    //// Assert that encrypting w with Qs produces ew.
    component p = PoseidonEncryptCheck(N*N);

    for (var i = 0; i < lCyphertext; i++) {
        p.ciphertext[i] <== ew[i];
    }

    for (var i = 0; i < N; i++) {
        for (var j = 0; j < N; j++) {
            p.message[i*N + j] <== w[i][j];
        }
    }
    
    component sharedKey = FromatSharedKey();
    sharedKey.pointX[0] <== Qs[0][0];
    sharedKey.pointX[1] <== Qs[0][1];
    sharedKey.pointX[2] <== Qs[0][2];
    sharedKey.pointX[3] <== Qs[0][3];

    p.nonce <== nonce;
    p.key[0] <== sharedKey.ks[0];
    p.key[1] <== sharedKey.ks[1];
    p.out === 1;
    
}

