// Exercise 5 for Crypto Camp week 1
// Mara van Der Laan 2025
// SPDX-License-Identifier: MIT
use bnum::types::U256;
use bnum::BUint;
use bnum::cast::CastFrom;

//////////////////// Utilities.

/// The unsigned bignum type to use.
type UBig = U256;

/// Compute a*b mod c (pre: a<c and b<c)
fn mul_mod(a: UBig, b: UBig, c: UBig) -> UBig {
    type UDoubleBig = BUint<{((UBig::BITS * 2) / 64) as usize}>;
    let (l, h) = a.widening_mul(b);
    // TODO: does this actually need a double-width type, would computing
    // h * ((1 << UBig::BITS) % c) + l  mod c do?
    // (yes, but this doesn't work around the need for a larger type)
    let r = UDoubleBig::cast_from(h).shl(UBig::BITS) + UDoubleBig::cast_from(l);
    UBig::cast_from(r % UDoubleBig::cast_from(c))
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

//////////////////// Generic group implementation.

/// An element of a finite Abelian group
pub trait GroupElement {
    fn identity(self) -> Self;
    fn order(self) -> UBig;

    fn operator(self, other: Self) -> Self;
}

/// Compute a^b
fn group_exp<T: GroupElement + Copy>(a: T, b: UBig) -> T {
    let mut res = a.identity();
    let mut cur = a;
    for bit in 0..UBig::BITS {
        if b.bit(bit) {
            res = res.operator(cur);
        }
        cur = cur.operator(cur);
    }
    res
}

/// Compute a^-1
fn group_inv<T: GroupElement + Copy>(a: T) -> T {
    group_exp(a, a.order().sub(UBig::ONE))
}

//////////////////// ElGamal implementation.

/// ElGamal domain parameters.
struct DomainParameters<T: GroupElement> {
    g: T,
}

/// ElGamal public key.
struct PubKey<T: GroupElement> {
    y: T,
}

/// ElGamal private key.
struct PrivKey<T: GroupElement> {
    x: UBig,
    pubkey: PubKey<T>,
}

impl<T: GroupElement + Copy> DomainParameters<T> {
    /// Construct an ElGamal keypair from the private key value.
    fn from_priv(&self, x: UBig) -> PrivKey<T> {
        let y = group_exp(self.g, x);

        PrivKey {
            x: x,
            pubkey: PubKey {
                y: y,
            }
        }
    }

    /// Generate a new ElGamal keypair.
    #[allow(dead_code)]
    fn gen_keypair(&self) -> PrivKey<T> {
        self.from_priv(rand_key_mod_p(self.g.order()))
    }

    /// ElGamal encrypt a message.
    fn encrypt(&self, pubkey: &PubKey<T>, m: T) -> (T, T) {
        // Ephermal key.
        let k = rand_key_mod_p(self.g.order());
        let c1 = group_exp(self.g, k);
        let c2 = m.operator(group_exp(pubkey.y, k));
        (c1, c2)
    }

    /// ElGamal decrypt a message.
    fn decrypt(&self, privkey: &PrivKey<T>, c1: T, c2: T) -> T {
        group_inv(group_exp(c1, privkey.x)).operator(c2)
    }
}

//////////////////// Specific group implementation.

#[derive(Clone, Copy)]
struct ZStarElement {
    v: UBig,
    p: UBig,
}

impl GroupElement for ZStarElement {
    /// Multiplicative identity
    fn identity(self) -> Self {
        ZStarElement { v: UBig::ONE, p: self.p }
    }
    /// Order of ZStar is p - 1
    fn order(self) -> UBig {
        self.p.sub(UBig::ONE)
    }

    fn operator(self, other: Self) -> Self {
        ZStarElement { v: mul_mod(self.v, other.v, self.p), p: self.p }
    }
}

//////////////////// Main testing.

fn main() {
    /* (domain parameters) */
    let params: DomainParameters<ZStarElement> = DomainParameters {
        g: ZStarElement {
            v: UBig::parse_str_radix("937a57cdc95f6717f6d90b4286568c2c9aca750bfd1069b00cbf28abc17ba191", 16),
            p: UBig::parse_str_radix("eacb15fa75b90bbbe13663a539814e3318ec6b21cc5d51c1a8182484ffa90edf", 16),
        },
    };

    /* (test keypair) */
    let privkey = params.from_priv(UBig::parse_str_radix("805bc6597f53ef8feb7bc4490eb33579bc9ed7b6ad44390e3ed29e5b4df9e52a", 16));
    println!("x {:x}", privkey.x);
    println!("y {:x}", privkey.pubkey.y.v);

    let m = ZStarElement { v: UBig::parse_str_radix("12345", 16), p: params.g.p };
    let (c1, c2) = params.encrypt(&privkey.pubkey, m);
    println!("c1 {:x}", c1.v);
    println!("c2 {:x}", c2.v);
    let m2 = params.decrypt(&privkey, c1, c2);
    println!("m2 {:x}", m2.v);
}
