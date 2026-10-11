pragma circom 2.1.6;
// Par-weighted average spread over N bonds, in tenths of a basis point, rounded half up.
//
//   spread_i = y_i - b_i                       (yields in thousandths of a percent = tenths of a bp)
//   R        = round( sum(w_i * spread_i) / sum(w_i) )
//
// The yields y (ICE evaluated yields) and b (benchmark yields) come from two vendor deliveries; the weights w
// (par held) are the firm's and stay private. Each input vector is bound to a Poseidon commitment that was
// signed and published before the calculation: the vendor's delivery records carry Cy and Cb, and the firm
// registered Cw. Each commitment also covers the bond identifiers (id), and the same id signals feed all three,
// so the yields, the benchmarks and the weights are proven to line up bond by bond without naming the bonds.
//   C = Poseidon(Poseidon(id[0..N-1]), Poseidon(v[0..N-1]), salt)
// Public signals: [Cy, Cb, Cw, R]. Nothing else about id, y, b or w is revealed.
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

template SpreadPassport(N) {
    signal input id[N];
    signal input y[N];  signal input ys;
    signal input b[N];  signal input bs;
    signal input w[N];  signal input ws;
    signal input Cy; signal input Cb; signal input Cw; signal input R;

    component hid = Poseidon(N); component hy = Poseidon(N); component hb = Poseidon(N); component hw = Poseidon(N);
    for (var i = 0; i < N; i++) { hid.inputs[i] <== id[i]; hy.inputs[i] <== y[i]; hb.inputs[i] <== b[i]; hw.inputs[i] <== w[i]; }
    component cy = Poseidon(3); cy.inputs[0] <== hid.out; cy.inputs[1] <== hy.out; cy.inputs[2] <== ys;
    component cb = Poseidon(3); cb.inputs[0] <== hid.out; cb.inputs[1] <== hb.out; cb.inputs[2] <== bs;
    component cw = Poseidon(3); cw.inputs[0] <== hid.out; cw.inputs[1] <== hw.out; cw.inputs[2] <== ws;
    Cy === cy.out; Cb === cb.out; Cw === cw.out;

    // Ranges keep every value small enough that nothing wraps in the field:
    // yields below 2^20 (1048.575%), spreads 0 to 2^20, weights below 2^40.
    component ry[N]; component rb[N]; component rd[N]; component rw[N];
    signal d[N]; signal p[N + 1]; signal wsum[N + 1];
    p[0] <== 0; wsum[0] <== 0;
    for (var i = 0; i < N; i++) {
        ry[i] = Num2Bits(20); ry[i].in <== y[i];
        rb[i] = Num2Bits(20); rb[i].in <== b[i];
        d[i] <== y[i] - b[i];
        rd[i] = Num2Bits(20); rd[i].in <== d[i];
        rw[i] = Num2Bits(40); rw[i].in <== w[i];
        p[i + 1] <== p[i] + w[i] * d[i];
        wsum[i + 1] <== wsum[i] + w[i];
    }
    signal S <== p[N]; signal W <== wsum[N];
    component wz = IsZero(); wz.in <== W; wz.out === 0;

    // R = floor((2S + W) / 2W): 0 <= 2S + W - 2W*R < 2W
    component rr = Num2Bits(24); rr.in <== R;
    signal twoWR <== 2 * W * R;
    signal rem <== 2 * S + W - twoWR;
    component remBits = Num2Bits(66); remBits.in <== rem;
    component lt = LessThan(66); lt.in[0] <== rem; lt.in[1] <== 2 * W; lt.out === 1;
}
component main {public [Cy, Cb, Cw, R]} = SpreadPassport(8);
