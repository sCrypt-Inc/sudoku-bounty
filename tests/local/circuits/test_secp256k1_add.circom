pragma circom 2.0.2;

include "../../../../circuit/ecdsa/secp256k1.circom";

component main {public [a, b]} = Secp256k1AddUnequal(64, 4);
