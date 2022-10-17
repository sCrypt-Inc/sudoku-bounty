pragma circom 2.0.2;

include "../../../circuit/util/poseidon.circom";


component main {public [ciphertext, message, nonce, key]} = PoseidonEncryptCheck(3);