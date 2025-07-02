// Exercise 5 for Crypto Camp week 1
// Mara van Der Laan 2025
// SPDX-License-Identifier: MIT
use bnum::types::U512;
use bnum::BUint;
use bnum::cast::CastFrom;

//////////////////// Utilities.

/// The unsigned bignum type to use.
type UBig = U512;

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
    fn encrypt_k(&self, pubkey: &PubKey<T>, m: T, k: UBig) -> (T, T) {
        let c1 = group_exp(self.g, k);
        let c2 = m.operator(group_exp(pubkey.y, k));
        (c1, c2)
    }

    /// ElGamal encrypt a message.
    fn encrypt(&self, pubkey: &PubKey<T>, m: T) -> (T, T) {
        // Ephermal key.
        let k = rand_key_mod_p(self.g.order());
        self.encrypt_k(pubkey, m, k)
    }

    /// ElGamal decrypt a message.
    fn decrypt(&self, privkey: &PrivKey<T>, c1: T, c2: T) -> T {
        group_inv(group_exp(c1, privkey.x)).operator(c2)
    }
}

//////////////////// Specific group implementation.

#[derive(Clone, Copy)]
struct ZStarElement {
    /// Value of element.
    v: UBig,
    /// Modulus of group (yes, ideally this should be on a parameter struct, not here).
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elgamal_tests() {
        // https://gist.github.com/devinrsmith/19256389288b7e9ff5685a658f9b22d1#file-found_elgamal_test_vectors-csv
        struct Test {
            p: UBig,
            g: UBig,
            x: UBig,
            k: UBig,
            m: UBig,
            a: UBig,
            b: UBig,
        }
        const CASES: &[Test] = &[
            Test {
                p: UBig::parse_str_radix("71", 10),
                g: UBig::parse_str_radix("33", 10),
                x: UBig::parse_str_radix("62", 10),
                k: UBig::parse_str_radix("31", 10),
                m: UBig::parse_str_radix("15", 10),
                a: UBig::parse_str_radix("62", 10),
                b: UBig::parse_str_radix("18", 10),
            },
            Test {
                p: UBig::parse_str_radix("23", 10),
                g: UBig::parse_str_radix("11", 10),
                x: UBig::parse_str_radix("6", 10),
                k: UBig::parse_str_radix("3", 10),
                m: UBig::parse_str_radix("10", 10),
                a: UBig::parse_str_radix("20", 10),
                b: UBig::parse_str_radix("22", 10),
            },
            Test {
                p: UBig::parse_str_radix("809", 10),
                g: UBig::parse_str_radix("3", 10),
                x: UBig::parse_str_radix("68", 10),
                k: UBig::parse_str_radix("89", 10),
                m: UBig::parse_str_radix("100", 10),
                a: UBig::parse_str_radix("345", 10),
                b: UBig::parse_str_radix("517", 10),
            },
            Test {
                p: UBig::parse_str_radix("17", 10),
                g: UBig::parse_str_radix("6", 10),
                x: UBig::parse_str_radix("5", 10),
                k: UBig::parse_str_radix("10", 10),
                m: UBig::parse_str_radix("13", 10),
                a: UBig::parse_str_radix("15", 10),
                b: UBig::parse_str_radix("9", 10),
            },
            Test {
                p: UBig::parse_str_radix("84265675725482892459719348378630146162719620409152809167814480007059199482163", 10),
                g: UBig::parse_str_radix("5", 10),
                x: UBig::parse_str_radix("2799014790424892046701478888900891009403869701173893426", 10),
                k: UBig::parse_str_radix("23517683968368899022119256606644551548285683288848885921", 10),
                m: UBig::parse_str_radix("87521618088882658227876453", 10),
                a: UBig::parse_str_radix("22954586883013884818653063688294540134886732496160582262267014428782771199687", 10),
                b: UBig::parse_str_radix("56046128113101346099694619669629128017849277484825379502821514323706183544424", 10),
            },
            Test {
                p: UBig::parse_str_radix("12658517083168187407924345155971956101250996576825115113297001855799796437288935576230034157578333666497170430505565580165565829633685607504706642034926119", 10),
                g: UBig::parse_str_radix("7", 10),
                x: UBig::parse_str_radix("2001688878140630728014209681954697141876038523595247208", 10),
                k: UBig::parse_str_radix("5446024688717452254835115775456957961297236108858862823", 10),
                m: UBig::parse_str_radix("87521618088882658227876453", 10),
                a: UBig::parse_str_radix("2150519483988769855483983776372336742288374425191291528256965705108393490638750082340115568718132372731853110762124400441550538499580316268601341087676203", 10),
                b: UBig::parse_str_radix("1540471266850557563382406324432354117072109094950140952195099581066490559252112349492583688225692526496193879919152401794896907007394565292272866724291488", 10),
            },
        ];
        for case in CASES {
            let params: DomainParameters<ZStarElement> = DomainParameters {
                g: ZStarElement {
                    v: case.g,
                    p: case.p,
                },
            };

            /* test encrypt */
            let privkey = params.from_priv(case.x);
            let m = ZStarElement { v: case.m, p: params.g.p };
            let (c1, c2) = params.encrypt_k(&privkey.pubkey, m, case.k);
            assert_eq!(c1.v, case.a);
            assert_eq!(c2.v, case.b);

            /* test decrypt */
            let c1_d = ZStarElement { v: case.a, p: params.g.p };
            let c2_d = ZStarElement { v: case.b, p: params.g.p };
            let m_d = params.decrypt(&privkey, c1_d, c2_d);
            assert_eq!(m_d.v, case.m);
        }
    }
}
