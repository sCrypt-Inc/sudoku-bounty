pragma circom 2.0.2;

include "../node_modules/circomlib/circuits/sha256/sha256.circom";

include "ecdsa/ecdsa.circom";
include "ecdsa/secp256k1.circom";
include "poseidon/poseidon.circom";
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

template ConcatBitArr(inSize) {
    signal input b0[inSize];
    signal input b1[inSize];
    signal output out[inSize * 2];
    
    for (var j = 0; j < inSize; j++) {
        out[j] <== b0[j];
    }
    for (var j = 0; j < inSize; j++) {
        out[j + inSize] <== b1[j];
    }
}

template Num2BitsMultipleReverse(nNums, nBits) {
    signal input in[nNums];
    signal output out[nNums][nBits];

    for (var i = 0; i < nNums; i++) {
        var lc1=0;
        var e2=1;
        for (var j = 0; j < nBits; j++) {
            out[i][nBits - 1 - j] <-- (in[i] >> j) & 1;
            out[i][nBits - 1 - j] * (out[i][nBits - 1 - j] - 1 ) === 0;
            lc1 += out[i][nBits - 1 - j] * e2;
            e2 = e2+e2;
        }
        lc1 === in[i];
    }
}

template Point2Bits() {
    signal input in[2][4];
    signal output out[512];

    component bits0 = Num2Bits(64);
    component bits1 = Num2Bits(64);
    component bits2 = Num2Bits(64);
    component bits3 = Num2Bits(64);
    component bits4 = Num2Bits(64);
    component bits5 = Num2Bits(64);
    component bits6 = Num2Bits(64);
    component bits7 = Num2Bits(64);
    
    bits0.in <== in[0][0];
    bits1.in <== in[0][1];
    bits2.in <== in[0][2];
    bits3.in <== in[0][3];
    bits4.in <== in[1][0];
    bits5.in <== in[1][1];
    bits6.in <== in[1][2];
    bits7.in <== in[1][3];
    
    for (var i = 0; i < 64; i++) {
        out[i] <== bits3.out[63 - i];
    }
    for (var i = 0; i < 64; i++) {
        out[i + 64] <== bits2.out[63 - i];
    }
    for (var i = 0; i < 64; i++) {
        out[i + 128] <== bits1.out[63 - i];
    }
    for (var i = 0; i < 64; i++) {
        out[i + 192] <== bits0.out[63 - i];
    }
    for (var i = 0; i < 64; i++) {
        out[i + 256] <== bits7.out[63 - i];
    }
    for (var i = 0; i < 64; i++) {
        out[i + 320] <== bits6.out[63 - i];
    }
    for (var i = 0; i < 64; i++) {
        out[i + 384] <== bits5.out[63 - i];
    }
    for (var i = 0; i < 64; i++) {
        out[i + 448] <== bits4.out[63 - i];
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
    
    component bitsKs0 = ConcatBitArr(64);
    component bitsKs1 = ConcatBitArr(64);
    
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
//                in this case this could be just N * N + 1
template Main(N, sqrtN, lCyphertext) {

    // Private inputs:
    signal input w[N][N];           // Solition to the specified puzzle.
    signal input db[4];             // Seller (Bob) private key.
    signal input Qs[2][4];          // Shared (symmetric) key. Used to encrypt w.
    
    // "Public" inputs that are still passed as private to reduce verifier size on chain:
    signal input Qa[2][4];          // Buyer (Alice) public key.
                                    // TODO: Could also be hardcoded into the circuit like the unsolved puzzle.
    signal input Qb[2][4];          // Seller (Bob) public key.
    signal input nonce;             // Needed to encrypt/decrypt xy.
    signal input ew[lCyphertext];   // Encrypted solution to puzzle.

    // Public inputs:
    signal input Hpub[2];            // Hash of inputs that are supposed to be public.

    // Unsolved sudoku board.
    var unsolved[N][N] = [
        [0, 0, 0, 0, 0, 6, 0, 0, 0],
        [0, 0, 7, 2, 0, 0, 8, 0, 0],
        [9, 0, 6, 8, 0, 0, 0, 1, 0],
        [3, 0, 0, 7, 0, 0, 0, 2, 9],
        [0, 0, 0, 0, 0, 0, 0, 0, 0],
        [4, 0, 0, 5, 0, 0, 0, 7, 0],
        [6, 5, 0, 1, 0, 0, 0, 0, 0],
        [8, 0, 1, 0, 5, 0, 3, 0, 0],
        [7, 9, 2, 0, 0, 0, 0, 0, 4]
    ];
    
    //// Assert that public inputs hash to Hpub.
    component ewBitsByPart = Num2BitsMultipleReverse(lCyphertext, 256);
    for (var i = 0; i < lCyphertext; i++) {
        ewBitsByPart.in[i] <== ew[i];
    }
    
    component QaBits = Point2Bits();
    component QbBits = Point2Bits();
    for (var i = 0; i < 4; i++) {
        QaBits.in[0][i] <== Qa[0][i];
        QaBits.in[1][i] <== Qa[1][i];
        QbBits.in[0][i] <== Qb[0][i];
        QbBits.in[1][i] <== Qb[1][i];
    }
    
    component nonceBits = Num2Bits(256);
    nonceBits.in <== nonce;

    component hashCheck = Sha256(512 * 2 + 256 + lCyphertext * 256);

    for (var i = 0; i < 512; i++) {
        hashCheck.in[i] <== QaBits.out[i];
        hashCheck.in[i + 512] <== QbBits.out[i];
    }

    for (var i = 0; i < 256; i++) {
        hashCheck.in[i + 1024] <== nonceBits.out[255 - i];
    }

    for (var i = 0; i < lCyphertext; i++) {
        for (var j = 0; j < 256; j++) {
            hashCheck.in[i * 256 + j + 1280] <== ewBitsByPart.out[i][j];
        }
    }

    component Hpub0 = BitArr2Num(128);
    component Hpub1 = BitArr2Num(128);
    for (var i = 0; i < 128; i++) {
        Hpub0.in[i] <== hashCheck.out[i];
        Hpub1.in[i] <== hashCheck.out[i + 128];
    }
    Hpub[0] === Hpub0.out;
    Hpub[1] === Hpub1.out;

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

