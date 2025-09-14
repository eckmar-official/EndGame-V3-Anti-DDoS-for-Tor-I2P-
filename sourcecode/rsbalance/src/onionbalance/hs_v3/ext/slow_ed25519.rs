use num_bigint::BigInt;
use num_traits::{Euclid, One, ToPrimitive, Zero};
use std::ops::Div;

const B_CONST: usize = 256;

lazy_static! {
    static ref BY_CONST: BigInt = BigInt::from(4) * inv(BigInt::from(5));
    static ref BX_CONST: BigInt = xrecover(&BY_CONST);
    static ref Q_CONST: BigInt = BigInt::from(2).pow(255) - 19;
    pub static ref BB_CONST: [BigInt; 2] = [BX_CONST.clone() % &Q_CONST.clone(), BY_CONST.clone() % &Q_CONST.clone()];
    static ref D_CONST: BigInt = BigInt::from(-121665) * inv(BigInt::from(121666));
    static ref I_CONST: BigInt = expmod(
        &BigInt::from(2),
        (Q_CONST.clone() - BigInt::one()) / BigInt::from(4),
        &Q_CONST.clone()
    );
}

pub fn encode_point(p: &[BigInt; 2]) -> [u8; 32] {
    let one = BigInt::one();
    let x = &p[0];
    let y = &p[1];
    let mut bits = [0u8; B_CONST];
    for i in 0..B_CONST - 1 {
        bits[i] = ((y >> i) & &one).to_u8().expect("always valid");
    }
    bits[B_CONST - 1] = (x & one).to_u8().expect("always valid");
    let mut bytes = [0u8; B_CONST / 8];
    for i in 0..B_CONST / 8 {
        let mut sum = 0u8;
        for j in 0..8 {
            let idx = i * 8 + j;
            sum += bits[idx] << j;
        }
        bytes[i] = sum;
    }
    bytes
}

pub fn decode_int(s: &[u8]) -> BigInt {
    let mut sum = BigInt::zero();
    for i in 0..256 {
        let e = BigInt::from(2).pow(i as u32);
        let m = bit(s, i);
        sum += e * m;
    }
    sum
}

pub fn bit(h: &[u8], i: usize) -> u8 {
    (h[i / 8] >> (i % 8)) & 1
}

pub fn scalarmult(p: &[BigInt; 2], e: &BigInt) -> [BigInt; 2] {
    let zero = BigInt::zero();
    let one = BigInt::one();
    if e == &zero {
        return [zero, one];
    }
    let mut q = scalarmult(p, &e.div(2));
    q = edwards(&q, &q);
    if e & &one == one {
        q = edwards(&q, p);
    }
    q
}

fn edwards(p: &[BigInt; 2], q: &[BigInt; 2]) -> [BigInt; 2] {
    let qc = Q_CONST.clone();
    let dc = D_CONST.clone();
    let x1 = &p[0];
    let y1 = &p[1];
    let x2 = &q[0];
    let y2 = &q[1];
    let x3 = (x1 * y2 + x2 * y1) * inv(1 + &dc * x1 * x2 * y1 * y2);
    let y3 = (y1 * y2 + x1 * x2) * inv(1 - &dc * x1 * x2 * y1 * y2);
    [x3 % &qc, y3 % &qc]
}

fn xrecover(y: &BigInt) -> BigInt {
    let qc = Q_CONST.clone();
    let xx: BigInt = ((y * y) - BigInt::one()) * (inv((D_CONST.clone() * y * y) + 1));
    let mut x = expmod(&xx, (&qc + 3) / 8, &qc);
    if ((&x * &x) - xx) % &qc != BigInt::zero() {
        x = (x * I_CONST.clone()) % &qc;
    }
    if &x % 2 != BigInt::zero() {
        x = &qc - x;
    }
    x
}

fn inv(x: BigInt) -> BigInt {
    let qc = Q_CONST.clone();
    expmod(&x, &qc - 2, &qc)
}

fn expmod(bp: &BigInt, e: BigInt, m: &BigInt) -> BigInt {
    if e == BigInt::zero() {
        return BigInt::one();
    }
    let mut t = expmod(bp, e.clone() / 2, m).pow(2) % m;
    let one = BigInt::one();
    if e & &one == one {
        t = (t * bp).rem_euclid(m);
    }
    t
}
