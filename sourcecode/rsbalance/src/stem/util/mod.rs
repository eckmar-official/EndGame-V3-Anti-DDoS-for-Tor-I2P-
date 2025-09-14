use num_bigint::BigInt;
use num_traits::{Euclid, One, ToPrimitive, Zero};
use sha3::Digest;
use std::str::FromStr;
use ed25519_dalek::VerifyingKey;

const B_CONST: usize = 256;

lazy_static! {
    static ref BY_CONST: BigInt = BigInt::from(4) * inv(BigInt::from(5));
    static ref BX_CONST: BigInt = xrecover(&BY_CONST);
    static ref Q_CONST: BigInt = BigInt::from(2).pow(255) - 19;
    // pub static ref BB_CONST: [BigInt; 2] = [BX_CONST.clone() % &Q_CONST.clone(), BY_CONST.clone() % &Q_CONST.clone()];
    static ref BB1_CONST: [BigInt; 4] = [BX_CONST.clone().modpow(&BigInt::one(), &Q_CONST.clone()), BY_CONST.clone()%Q_CONST.clone(), BigInt::one(), (BX_CONST.clone()*BY_CONST.clone())%Q_CONST.clone()];
    //var bB1 = []*big.Int{biMod(bx, q), biMod(by, q), bi(1), biMod(biMul(bx, by), q)}
    static ref D_CONST: BigInt = BigInt::from(-121665) * inv(BigInt::from(121666));
    static ref I_CONST: BigInt = expmod(&BigInt::from(2), (Q_CONST.clone() - BigInt::one()) / BigInt::from(4), &Q_CONST.clone());
    static ref L_CONST: BigInt = BigInt::from(2).pow(252) + BigInt::from_str("27742317777372353535851937790883648493").unwrap();
}

// BlindedSignWithTorKey this is identical to stem's hidden_service.py:_blinded_sign() but takes an
// extended private key (i.e. in tor format) as its argument, instead of the
// standard format that hazmat does. It basically omits the "extended the key"
// step and does everything else the same.
pub fn blinded_sign_with_tor_key(
    msg: Vec<u8>,
    identity_key: Vec<u8>,
    blinded_key: VerifyingKey,
    blinding_nonce: &[u8; 32],
) -> Vec<u8> {
    blinded_sign_p2(identity_key, msg, blinded_key, blinding_nonce)
}

pub fn blinded_sign(
    msg: Vec<u8>,
    identity_key: Vec<u8>,
    blinded_key: VerifyingKey,
    blinding_nonce: &[u8; 32],
) -> Vec<u8> {
    let identity_key_bytes = identity_key;
    // pad private identity key into an ESK (encrypted secret key)
    let mut tmp = sha2::Sha512::new();
    tmp.update(identity_key_bytes);
    let h: [u8; 64] = tmp.finalize().into();
    let mut sum = BigInt::zero();
    for i in 3..B_CONST - 2 {
        sum += BigInt::from(2).pow(i as u32) * bit(&h, i);
    }
    let a = BigInt::from(2).pow((B_CONST - 2) as u32) + sum;
    let mut k = [0u8; 32];
    k.copy_from_slice(&h[32..64]);
    let mut esk = [0u8; 64];
    esk[..32].copy_from_slice(&encode_int(a));
    esk[32..].copy_from_slice(&k);
    blinded_sign_p2(esk.to_vec(), msg, blinded_key, blinding_nonce)
}

fn blinded_sign_p2(
    esk: Vec<u8>,
    msg: Vec<u8>,
    blinded_key: VerifyingKey,
    blinding_nonce: &[u8; 32],
) -> Vec<u8> {
    // blind the ESK with this nonce
    let mut sum = BigInt::zero();
    for i in 3..B_CONST - 2 {
        let bit_res = BigInt::from(bit(blinding_nonce, i));
        sum += BigInt::from(2u8).pow(i as u32) * bit_res;
    }
    let mult = BigInt::from(2u8).pow((B_CONST - 2) as u32) + sum;
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&esk[..32]);
    let s = decode_int(&sk);
    let s_prime = (s * mult) % L_CONST.clone();
    let k = &esk[32..];
    let mut hasher = sha2::Sha512::new();
    hasher.update(&mut b"Derive temporary signing key hash input");
    hasher.update(&mut k.to_vec());
    let tmp: [u8; 64] = hasher.finalize().into();
    let encoded_s_prime = encode_int(s_prime);
    let mut blinded_esk = [0u8; 64];
    blinded_esk[..32].copy_from_slice(&encoded_s_prime);
    blinded_esk[32..].copy_from_slice(&tmp[..32]);

    // finally, sign the message

    let a = decode_int(blinded_esk[..32].try_into().expect("slice with correct length"));
    let mut lines: Vec<Vec<u8>> = Vec::new();
    for i in B_CONST / 8..B_CONST / 4 {
        lines.push(blinded_esk[i..i + 1].to_vec());
    }
    let mut to_hint: Vec<u8> = Vec::new();
    for line in lines {
        to_hint.extend(line);
    }
    to_hint.extend(msg.clone());
    let r = hint(&to_hint);
    let rr = scalarmult1(&BB1_CONST.clone(), r.clone());
    let mut tmp: Vec<u8> = Vec::new();
    tmp.extend(encode_point(rr.clone()));
    tmp.extend(blinded_key.to_bytes());
    tmp.extend(msg);
    let s = (r + hint(&tmp) * a) % L_CONST.clone();

    let mut out: Vec<u8> = Vec::new();
    out.extend(encode_point(rr));
    out.extend(encode_int(s));
    out
}

fn hint(m: &[u8]) -> BigInt {
    let mut hasher = sha2::Sha512::new();
    hasher.update(m);
    let h: [u8; 64] = hasher.finalize().into();
    let mut sum = BigInt::zero();
    for i in 0..B_CONST * 2 {
        sum += BigInt::from(2).pow(i as u32) * bit(&h, i);
    }
    sum
}

fn encode_int(y: BigInt) -> [u8; 32] {
    let mut bits = Vec::new();
    for i in 0..B_CONST {
        bits.push((&y >> i & BigInt::one()).to_u8().expect("always valid"));
    }
    let mut out = [0u8; 32];
    for i in 0..B_CONST / 8 {
        let mut sum = 0;
        for j in 0..8 {
            sum += &bits[i * 8 + j] << j;
        }
        out[i] = sum;
    }
    out
}

fn decode_int(s: &[u8; 32]) -> BigInt {
    let mut sum = BigInt::zero();
    for i in 0..256 {
        let e = BigInt::from(2).pow(i as u32);
        let m = bit(s, i);
        sum += e * m;
    }
    sum
}

pub fn blinded_pubkey(
    identity_key: VerifyingKey,
    blinding_nounce: &[u8; 32],
) -> anyhow::Result<VerifyingKey> {
    let ed25519b = 256u32;
    let mut sum = BigInt::zero();
    for i in 3..ed25519b - 2 {
        sum += BigInt::from(2).pow(i) * bit(blinding_nounce, i as usize);
    }
    let mult = BigInt::from(2).pow(ed25519b - 2) + sum;
    let p = decode_point(identity_key.as_bytes());
    let by = encode_point(scalarmult1(&p, mult.clone()));
    Ok(VerifyingKey::from_bytes(&by)?)
}

fn decode_point(s: &[u8; 32]) -> [BigInt; 4] {
    let q = &Q_CONST.clone();
    let mut sum = BigInt::zero();
    for i in 0..B_CONST - 1 {
        sum += BigInt::from(2).pow(i as u32) * bit(s, i);
    }
    let y = sum;
    let mut x = xrecover(&y);
    if &x & BigInt::one() != BigInt::from(bit(s, B_CONST - 1)) {
        x = q - &x;
    }
    let p = [x.clone(), y.clone(), BigInt::one(), x * y % q];
    if !is_on_curve(&p) {
        panic!("decoding point that is not on curve");
    }
    p
}

fn encode_point(p: [BigInt; 4]) -> [u8; 32] {
    let q = &Q_CONST.clone();
    let one = BigInt::one();
    let x = &p[0];
    let y = &p[1];
    let z = &p[2];
    let zi = &inv(z.clone());

    // From here, same as slow_ed
    let x = x * zi % q;
    let y = y * zi % q;
    let mut bits = [0u8; B_CONST];
    for i in 0..B_CONST - 1 {
        bits[i] = ((&y >> i) & &one).to_u8().expect("always valid");
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

fn scalarmult1(p: &[BigInt; 4], e: BigInt) -> [BigInt; 4] {
    if e == BigInt::zero() {
        return [BigInt::zero(), BigInt::one(), BigInt::one(), BigInt::zero()];
    }
    let mut q = scalarmult1(&p, &e / 2);
    q = edwards_double(&q);
    if e & BigInt::one() == BigInt::one() {
        q = edwards_add(&q, &p);
    }
    q
}

fn edwards_add(p: &[BigInt; 4], qp: &[BigInt; 4]) -> [BigInt; 4] {
    // This is formula sequence 'addition-add-2008-hwcd-3' from
    // http://www.hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html
    let d = &D_CONST.clone();
    let q = &Q_CONST.clone();
    let d1 = d.modpow(&BigInt::one(), q);
    let x1 = &p[0];
    let y1 = &p[1];
    let z1 = &p[2];
    let t1 = &p[3];
    let x2 = &qp[0];
    let y2 = &qp[1];
    let z2 = &qp[2];
    let t2 = &qp[3];
    let a = ((y1 - x1) * (y2 - x2)) % q;
    let b = ((y1 + x1) * (y2 + x2)) % q;
    let c = (t1 * 2 * d1 * t2) % q;
    let dd: BigInt = (z1 * 2 * z2) % q;
    let e = &b - &a;
    let f: BigInt = &dd - &c;
    let g: BigInt = &dd + &c;
    let h = &b + &a;
    let x3: BigInt = &e * &f;
    let y3: BigInt = &g * &h;
    let t3: BigInt = &e * &h;
    let z3: BigInt = &f * &g;
    [
        x3.modpow(&BigInt::one(), q),
        y3.modpow(&BigInt::one(), q),
        z3.modpow(&BigInt::one(), q),
        t3.modpow(&BigInt::one(), q),
    ]
}

fn edwards_double(p: &[BigInt; 4]) -> [BigInt; 4] {
    // This is formula sequence 'dbl-2008-hwcd' from
    // http://www.hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html
    let q = &Q_CONST.clone();
    let x1 = &p[0];
    let y1 = &p[1];
    let z1 = &p[2];
    let a = (x1 * x1) % q;
    let b = (y1 * y1) % q;
    let c = (2 * z1 * z1) % q;
    let e = (((x1 + y1) * (x1 + y1) - &a) - &b) % q;
    let g: BigInt = &a * -1 + &b;
    let f: BigInt = &g - &c;
    let h = (&a * -1) - &b;
    let x3: BigInt = &e * &f;
    let y3: BigInt = &g * &h;
    let t3: BigInt = &e * &h;
    let z3: BigInt = &f * &g;
    [
        x3.modpow(&BigInt::one(), q),
        y3.modpow(&BigInt::one(), q),
        z3.modpow(&BigInt::one(), q),
        t3.modpow(&BigInt::one(), q),
    ]
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

fn is_on_curve(p: &[BigInt; 4]) -> bool {
    let d = &D_CONST.clone();
    let q = &Q_CONST.clone();
    let x = &p[0];
    let y = &p[1];
    let z = &p[2];
    let t = &p[3];
    z % q != BigInt::zero() && (x * y) % q == (z * t) % q && (y * y - x * x - z * z - d * t * t) % q == BigInt::zero()
}

fn bit(h: &[u8], i: usize) -> u8 {
    (h[i / 8] >> (i % 8)) & 1
}

#[cfg(test)]
mod tests {
    use crate::stem::util::{blinded_pubkey, blinded_sign, edwards_add, edwards_double};
    use base64::{engine::general_purpose, Engine as _};
    use num_bigint::BigInt;
    use std::str::FromStr;
    use ed25519_dalek::pkcs8::DecodePrivateKey;
    use ed25519_dalek::{SigningKey, VerifyingKey};

    #[test]
    fn test_blinded_sign() {
        let msg = general_purpose::STANDARD
            .decode("AQgABvn+AUmtuF1+Nb/kJ67y1U0lI7HiDjRJwHHY+sQrHlBKomR3AQAgBAAtL5DBE1Moh7A+AGrzgWhcHOBo/W3lyhcLeip0LuI8Xw==")
            .unwrap();
        let identity_key_pem = r#"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIMjdAAyeb8pU3CzRK2z+yKSgWi0R33mfeAPpVnktRrwA
-----END PRIVATE KEY-----"#;
        let identity_key = SigningKey::from_pkcs8_pem(identity_key_pem).unwrap();
        let blinded_key = general_purpose::STANDARD.decode("LS+QwRNTKIewPgBq84FoXBzgaP1t5coXC3oqdC7iPF8=").unwrap();
        let blinding_nonce = general_purpose::STANDARD.decode("ljbKEFzZGbd3ZI29J67XTs6JV3Glp+uieQ5yORMhmdg=").unwrap();
        let expected = "xIrhGFs3VZKbV36zqCcudaWN0+K8s6zRRr5qki1uz/HjBL80SQ0HEirDp4DnNBAeYDIjNJwmrgQe6IU8ESHzDg==";
        let blinded_key = VerifyingKey::from_bytes(&blinded_key.try_into().unwrap()).unwrap();
        let res = blinded_sign(
            msg,
            identity_key.as_bytes().to_vec(),
            blinded_key,
            blinding_nonce.as_slice().try_into().unwrap(),
        );
        assert_eq!(expected, general_purpose::STANDARD.encode(res));
    }

    #[test]
    fn test_blinded_pubkey() {
        let identity_key = VerifyingKey::from_bytes(&[
            184, 58, 199, 21, 139, 126, 145, 105, 1, 226, 240, 164, 161, 114, 133, 93, 68, 230, 232, 188, 78, 138, 21,
            47, 2, 74, 187, 210, 112, 42, 131, 46,
        ])
        .unwrap();
        let blinding_nounce: &[u8; 32] = &[
            19, 138, 84, 191, 232, 12, 145, 105, 120, 251, 222, 150, 93, 217, 185, 143, 219, 252, 132, 76, 44, 165,
            186, 31, 159, 54, 222, 185, 200, 45, 138, 156,
        ];
        let res = blinded_pubkey(identity_key, blinding_nounce).unwrap();
        assert_eq!(
            "amgMpVcyvV1np1WnmZfbXrQQ8x3E/2hg6Cw7VGl6KEg=",
            general_purpose::STANDARD.encode(res)
        );
    }

    #[test]
    fn test_edwards_add() {
        let p: &[BigInt; 4] = &[
            BigInt::from_str("33280095491252177242230972736793195764486192269606311769743138130516652103180").unwrap(),
            BigInt::from_str("28267627765551149876920304632299252130840282052877251303625872724446071043214").unwrap(),
            BigInt::from_str("6117444033391762485753342782543429711275604385761971686625191882866690582038").unwrap(),
            BigInt::from_str("31547418022311671693994940433825202990679863225266553726085793490130479362644").unwrap(),
        ];
        let q: &[BigInt; 4] = &[
            BigInt::from_str("15112221349535400772501151409588531511454012693041857206046113283949847762202").unwrap(),
            BigInt::from_str("46316835694926478169428394003475163141307993866256225615783033603165251855960").unwrap(),
            BigInt::from_str("1").unwrap(),
            BigInt::from_str("46827403850823179245072216630277197565144205554125654976674165829533817101731").unwrap(),
        ];
        let exp: &[BigInt; 4] = &[
            BigInt::from_str("14591232216964962521349785457176623778348084585962116592401043271866696492603").unwrap(),
            BigInt::from_str("15501591954339422883898223213430929859571639827276692901775721833747536932958").unwrap(),
            BigInt::from_str("52139910817624834557542446504334255388794630927383646294941047398865830415672").unwrap(),
            BigInt::from_str("42281670404254854495522880803212066655478921718230252296702667003696606317170").unwrap(),
        ];
        assert_eq!(exp, &edwards_add(p, q))
    }

    #[test]
    fn test_edwards_double() {
        let p: &[BigInt; 4] = &[
            BigInt::from_str("34071718733060099390029600740796060162684374589305532719082827354508254922929").unwrap(),
            BigInt::from_str("26256519042819668898113733987732481034958046382423949503856308234802784168691").unwrap(),
            BigInt::from_str("4").unwrap(),
            BigInt::from_str("15776516734323113904564264044340718874278300232034403514842857660485622813315").unwrap(),
        ];
        let res = edwards_double(p);
        assert_eq!(
            BigInt::from_str("20725374641820191273410445984186716902701242373113185672212998177297030125683").unwrap(),
            res[0]
        );
        assert_eq!(
            BigInt::from_str("51227780299532018684459252933088157171943546732559547596392138202515656712461").unwrap(),
            res[1]
        );
        assert_eq!(
            BigInt::from_str("46997361119111184959765989477630397375910456733744497277217459847777202059155").unwrap(),
            res[2]
        );
        assert_eq!(
            BigInt::from_str("29104159175811966481353973352437804792300652486694229972966311465022147582829").unwrap(),
            res[3]
        );
    }
}
