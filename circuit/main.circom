pragma circom 2.0.2;


// Circuit for proving the knowledge of the square root of a number.
// w * w = x
template Main() {

    signal private input w;
    signal private input db;
    signal input Qax;
    signal input Qay;
    signal input Qbx;
    signal input Qby;
    signal input ew;
    signal input x;

    x <== w * w;

}

component main = Main();

