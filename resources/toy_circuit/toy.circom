pragma circom 2.1.6;

template Main() {
    signal input a;
    signal input b;

    signal c <== a * b;

    c === 6;
}

component main { public [ a ] } = Main();
