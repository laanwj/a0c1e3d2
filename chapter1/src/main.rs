// Exercises for Crypto Camp week 1
// Mara van Der Laan 2025
// SPDX-License-Identifier: MIT
use bnum::types::U256;
use bnum::BUint;
use bnum::cast::As;

/// The unsigned fixed-size bignum type to use.
type UBig = U256;

/// Compute a+b mod c (pre: a<c and b<c)
#[allow(dead_code)]
fn add_mod(a: UBig, b: UBig, c: UBig) -> UBig {
    let (l, h) = a.carrying_add(b, false);
    if h { // Carry
        l + c.wrapping_neg()
    } else if l >= c { // No carry
        l - c
    } else {
        l
    }
}

/// Compute a*b mod c (pre: a<c and b<c)
#[allow(dead_code)]
fn mul_mod(a: UBig, b: UBig, c: UBig) -> UBig {
    type UDoubleBig = BUint<{((UBig::BITS * 2) / 64) as usize}>;
    let (l, h) = a.widening_mul(b);
    // TODO: does this actually need a double-width type, would computing
    // h * ((1 << UBig::BITS) % c) + l  mod c do?
    // (yes, but this doesn't work around the need for a larger type)
    let r = h.as_::<UDoubleBig>().shl(UBig::BITS) + l.as_::<UDoubleBig>();
    (r % c.as_::<UDoubleBig>()).as_::<UBig>()
}

/// Compute a^b mod c (pre: a<c)
#[allow(dead_code)]
fn exp_mod(a: UBig, b: UBig, c: UBig) -> UBig {
    let mut res = UBig::ONE;
    let mut cur = a;
    for bit in 0..UBig::BITS {
        if b.bit(bit) {
            res = mul_mod(res, cur, c);
        }
        cur = mul_mod(cur, cur, c);
    }
    res
}

/// Compute modular inverse of a mod p (pre: a<p, p>2)
#[allow(dead_code)]
fn inv_mod(a: UBig, p: UBig) -> UBig {
    // Fermat's little theorem: a ^ (p-1) = 1 (mod p)
    // This means that a * (a ^ (p-2)) = 1 (mod p)
    exp_mod(a, p.sub(2.as_()), p)
}

/// Generate random key mod p
#[allow(dead_code)]
fn rand_key_mod_p(p: UBig) -> UBig {
    // Bitmask to trim random bits.
    let bitmask = p.wrapping_next_power_of_two().wrapping_sub(UBig::ONE);
    let mut buf = [0u8; (UBig::BITS/8) as usize];
    loop {
        getrandom::fill(&mut buf).ok();
        let r = UBig::from_be_slice(&buf).unwrap() & bitmask;
        if r < p {
            return r;
        }
    }
}

/// ElGamal domain parameters.
struct DomainParameters {
    p: UBig,
    g: UBig,
}

/// ElGamal public key.
struct PubKey {
    y: UBig,
}

/// ElGamal private key.
struct PrivKey {
    x: UBig,
    pubkey: PubKey,
}

/// Construct an ElGamal keypair from the private key value.
fn elgamal_from_priv(params: &DomainParameters, x: UBig) -> PrivKey {
    let y = exp_mod(params.g, x, params.p);

    PrivKey {
        x: x,
        pubkey: PubKey {
            y: y,
        }
    }
}

/// Generate a new ElGamal keypair.
fn elgamal_gen_keypair(params: &DomainParameters) -> PrivKey {
    elgamal_from_priv(params, rand_key_mod_p(params.p))
}

/// ElGamal encrypt a message.
fn elgamal_encrypt(params: &DomainParameters, pubkey: &PubKey, m: UBig) -> (UBig, UBig) {
    // Ephermal key.
    let k = rand_key_mod_p(params.p);
    let c1 = exp_mod(params.g, k, params.p);
    let c2 = mul_mod(m, exp_mod(pubkey.y, k, params.p), params.p);
    (c1, c2)
}

/// ElGamal decrypt a message.
fn elgamal_decrypt(params: &DomainParameters, privkey: &PrivKey, c1: UBig, c2: UBig) -> UBig {
    mul_mod(inv_mod(exp_mod(c1, privkey.x, params.p), params.p), c2, params.p)
}

fn main() {
    /* (domain parameters) */
    let params: DomainParameters = DomainParameters {
        p: UBig::parse_str_radix("eacb15fa75b90bbbe13663a539814e3318ec6b21cc5d51c1a8182484ffa90edf", 16),
        g: UBig::parse_str_radix("937a57cdc95f6717f6d90b4286568c2c9aca750bfd1069b00cbf28abc17ba191", 16),
    };

    /* (test keypair) */
    let privkey = elgamal_from_priv(&params, UBig::parse_str_radix("805bc6597f53ef8feb7bc4490eb33579bc9ed7b6ad44390e3ed29e5b4df9e52a", 16));
    println!("x {:x}", privkey.x);
    println!("y {:x}", privkey.pubkey.y);

    let m = UBig::parse_str_radix("12345", 16);
    let (c1, c2) = elgamal_encrypt(&params, &privkey.pubkey, m);
    println!("c1 {:x}", c1);
    println!("c2 {:x}", c2);
    let m2 = elgamal_decrypt(&params, &privkey, c1, c2);
    println!("m2 {:x}", m2);

    /* (random keypair) */
    /*
    let privkey2: PrivKey = elgamal_gen_keypair(&params);
    println!("x2 {:x}", privkey2.x);
    println!("y2 {:x}", privkey2.pk.y);
    */
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tests() {
        let a = UBig::parse_str_radix("a4b48d82c05eb1b29f73f4875e9839b97a971eea1c53e96c4658942f57b8dd8a", 16);
        let b = UBig::parse_str_radix("63fe5ad54fb61ed1f6e2713feddeac53c1e064417e80be452c186237601312d0", 16);
        let c = UBig::parse_str_radix("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16);

        assert_eq!(add_mod(a, b, c), UBig::parse_str_radix("8b2e8581014d084965665c74c76e60d3c77832b9ad4a7b17270f667b7cbf42b", 16));
        assert_eq!(mul_mod(a, b, c), UBig::parse_str_radix("d464555ce28a5038f079c5deb138d690ce17b5494e74cfd476ce90d8111a977f", 16));
        assert_eq!(add_mod(c.sub(UBig::ONE), c.sub(UBig::ONE), c), UBig::parse_str_radix("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d", 16));
        assert_eq!(exp_mod(a, 1.as_(), c), UBig::parse_str_radix("a4b48d82c05eb1b29f73f4875e9839b97a971eea1c53e96c4658942f57b8dd8a", 16));
        assert_eq!(exp_mod(a, 2.as_(), c), UBig::parse_str_radix("df8260402e69f79604fed563aa05a46ff0154fe44bf61395b47389fca7cd2456", 16));
        assert_eq!(exp_mod(a, 4.as_(), c), UBig::parse_str_radix("d7f85719c86c38a423b316e96edd305684a6945cfe09962755c5e710ecfe4c3e", 16));
        assert_eq!(exp_mod(a, 5.as_(), c), UBig::parse_str_radix("f7bebff2021a7c03b043fe20eaae900af6a46eec64feb01ea9143debb9615a61", 16));
        assert_eq!(exp_mod(a, 8.as_(), c), UBig::parse_str_radix("26e4819834c6d91cdfb5d2b58205bcab017629be932d83bce74a71f5fea5fe99", 16));
        assert_eq!(exp_mod(a, 0x12345678.as_(), c), UBig::parse_str_radix("8ac2769dd082094c4c4366047e17615673e9a8978da0f8ed9a53459a2f2c3294", 16));

        let p = c;
        for b in 1u32..10u32 {
            let b_big = UBig::from(b);
            let inv = inv_mod(b_big, p);
            let mult = mul_mod(b_big, inv, p);
            assert_eq!(mult, UBig::ONE);
            // println!("modinv({}) {}*{}={} mod p", p, b, inv, mult);
        }
    }
}
