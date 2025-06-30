// Exercises for Crypto Camp week 1
// Mara van Der Laan 2025
// SPDX-License-Identifier: MIT
use bnum::types::U256;
use bnum::BUint;
use bnum::cast::As;

/// The unsigned fixed-size bignum type to use.
type UBig = U256;

/// Compute a+b mod c (pre: a<c and b<c)
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
fn mul_mod(a: UBig, b: UBig, c: UBig) -> UBig {
    type UDoubleBig = BUint<{((UBig::BITS * 2) / 64) as usize}>;
    let (l, h) = a.widening_mul(b);
    // TODO: this doesn't actually need a double-width type, computing
    // h * ((1 << UBig::BITS) % c) + l  mod c    would do
    let r: UDoubleBig = h.as_::<UDoubleBig>().shl(UBig::BITS) + l.as_::<UDoubleBig>();
    (r % c.as_::<UDoubleBig>()).as_::<UBig>()
}

/// Compute a^b mod c (pre: a<c)
fn exp_mod(a: UBig, b: UBig, c: UBig) -> UBig {
    let mut res: UBig = UBig::ONE;
    let mut cur: UBig = a;
    for bit in 0..UBig::BITS {
        if b.bit(bit) {
            res = mul_mod(res, cur, c);
        }
        cur = mul_mod(cur, cur, c);
    }
    res
}

/// Compute modular inverse of a mod p (pre: a<p, p>2)
fn mod_inv(a: UBig, p: UBig) -> UBig {
    // Fermat's little theorem: a ^ (p-1) = 1 (mod p)
    // This means that a * (a ^ (p-2)) = 1 (mod p)
    exp_mod(a, p.sub(2.as_()), p)
}

/*
p 0xeacb15fa75b90bbbe13663a539814e3318ec6b21cc5d51c1a8182484ffa90edf
g 0x937a57cdc95f6717f6d90b4286568c2c9aca750bfd1069b00cbf28abc17ba191
x 0x805bc6597f53ef8feb7bc4490eb33579bc9ed7b6ad44390e3ed29e5b4df9e52a
y 0x9338b10b926178864fd45b8bf4994cb554188bf21856bb1cd19d2325eb97a250
*/

fn main() {
    let a: UBig = UBig::parse_str_radix("a4b48d82c05eb1b29f73f4875e9839b97a971eea1c53e96c4658942f57b8dd8a", 16);
    let b: UBig = UBig::parse_str_radix("63fe5ad54fb61ed1f6e2713feddeac53c1e064417e80be452c186237601312d0", 16);
    let c: UBig = UBig::parse_str_radix("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16);

    println!("0x{:x}", add_mod(a, b, c));
    println!("0x{:x}", mul_mod(a, b, c));
    println!("0x{:x}", add_mod(c.sub(1.as_()), c.sub(1.as_()), c));
    println!("0x{:x}", mul_mod(c.sub(1.as_()), c.sub(1.as_()), c));
    println!("exp 1 0x{:x}", exp_mod(a, 1.as_(), c));
    println!("exp 2 0x{:x}", exp_mod(a, 2.as_(), c));
    println!("exp 4 0x{:x}", exp_mod(a, 4.as_(), c));
    println!("exp 5 0x{:x}", exp_mod(a, 5.as_(), c));
    println!("exp 8 0x{:x}", exp_mod(a, 8.as_(), c));
    println!("exp 0x12345678 0x{:x}", exp_mod(a, 0x12345678.as_(), c));

    let p = c;
    for b in 1..10 {
        let inv = mod_inv(b.as_(), p.as_());
        println!("modinv({}) {}*{}={} mod p", p, b, inv, mul_mod(b.as_::<UBig>(), inv, p.as_::<UBig>()));
    }
}
