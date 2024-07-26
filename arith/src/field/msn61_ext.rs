use std::{
    iter::{Product, Sum},
    mem::size_of,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use super::{Field, FieldSerde};

// mod vectorized_msn61_ext;

const MSN61_MOD: u64 = (1u64 << 61) - 1;

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Msn61 {
    pub v: u64,
}

impl FieldSerde for Msn61 {
    fn serialize_into(&self, buffer: &mut [u8]) {
        buffer[..Msn61::SIZE].copy_from_slice(unsafe {
            std::slice::from_raw_parts(&self.v as *const u64 as *const u8, Msn61::SIZE)
        })
    }

    fn deserialize_from(buffer: &[u8]) -> Self {
        let ptr = buffer.as_ptr() as *const u64;
        let v = unsafe { ptr.read_unaligned() };
        v.into()
    }
}

impl Field for Msn61 {
    const NAME: &'static str = "Mersenne 61";
    const SIZE: usize = size_of::<u64>();
    const INV_2: Self = Msn61 { v: 1u64 << 60 };
    type BaseField = Msn61;

    fn zero() -> Self {
        Msn61 { v: 0 }
    }

    fn one() -> Self {
        Msn61 { v: 1 }
    }

    fn random_unsafe(mut rng: impl rand::RngCore) -> Self {
        rng.next_u64().into()
    }

    fn random_bool_unsafe(mut rng: impl rand::RngCore) -> Self {
        (rng.next_u32() & 1).into()
    }

    fn exp(&self, exponent: &Self) -> Self {
        let mut e = exponent.v;
        let mut res = Self::one();
        let mut t = *self;
        while e != 0 {
            let b = e & 1;
            if b == 1 {
                res *= t;
            }
            t = t * t;
            e >>= 1;
        }
        res
    }

    fn inv(&self) -> Option<Self> {
        if self.is_zero() {
            None
        } else {
            Some(self.exp(&Msn61 { v: MSN61_MOD - 2 }))
        }
    }

    fn add_base_elem(&self, rhs: &Self::BaseField) -> Self {
        *self + *rhs
    }

    fn add_assign_base_elem(&mut self, rhs: &Self::BaseField) {
        *self += *rhs
    }

    fn mul_base_elem(&self, rhs: &Self::BaseField) -> Self {
        *self * rhs
    }

    fn mul_assign_base_elem(&mut self, rhs: &Self::BaseField) {
        *self *= rhs
    }

    fn as_u32_unchecked(&self) -> u32 {
        self.v as u32
    }

    fn from_uniform_bytes(bytes: &[u8; 32]) -> Self {
        let ptr = bytes.as_ptr() as *const u64;
        let v = unsafe { ptr.read_unaligned() } as u64;
        v.into()
    }
}

impl Add<&Msn61> for Msn61 {
    type Output = Self;
    fn add(self, rhs: &Msn61) -> Self::Output {
        let mut vv = self.v + rhs.v;
        if vv >= MSN61_MOD {
            vv -= MSN61_MOD;
        }
        Msn61 { v: vv }
    }
}

impl Add for Msn61 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        self + &rhs
    }
}

impl AddAssign<&Msn61> for Msn61 {
    #[inline(always)]
    fn add_assign(&mut self, rhs: &Msn61) {
        *self = *self + rhs;
    }
}

impl AddAssign for Msn61 {
    #[inline(always)]
    fn add_assign(&mut self, rhs: Self) {
        *self += &rhs;
    }
}

impl<T: ::core::borrow::Borrow<Msn61>> Sum<T> for Msn61 {
    fn sum<I: Iterator<Item = T>>(iter: I) -> Self {
        iter.fold(Self::zero(), |acc, item| acc + item.borrow())
    }
}

impl Neg for Msn61 {
    type Output = Self;
    fn neg(self) -> Self::Output {
        Msn61 {
            v: if self.v == 0 { 0 } else { MSN61_MOD - self.v },
        }
    }
}

impl Sub<&Msn61> for Msn61 {
    type Output = Msn61;

    fn sub(self, rhs: &Msn61) -> Self::Output {
        self + &(-*rhs)
    }
}

impl Sub for Msn61 {
    type Output = Msn61;

    fn sub(self, rhs: Self) -> Self::Output {
        self - &rhs
    }
}

impl SubAssign<&Msn61> for Msn61 {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: &Msn61) {
        *self = *self - rhs;
    }
}

impl SubAssign for Msn61 {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: Self) {
        *self -= &rhs;
    }
}

impl From<u32> for Msn61 {
    #[inline(always)]
    fn from(x: u32) -> Self {
        Msn61 { v: x as u64 }
    }
}

impl From<u64> for Msn61 {
    #[inline(always)]
    fn from(x: u64) -> Self {
        Msn61 {
            v: msn61_try_sub(msn61_mod_u64(x)),
        }
    }
}

// when x < p^2, msn61_mod(x) < 2p
fn msn61_mod(x: u128) -> u64 {
    (x & MSN61_MOD as u128) as u64 + (x >> 61) as u64
}

fn msn61_mod_u64(x: u64) -> u64 {
    (x & MSN61_MOD) + (x >> 61)
}

fn msn61_try_sub(x: u64) -> u64 {
    if x < MSN61_MOD {
        x
    } else {
        x - MSN61_MOD
    }
}

impl Mul<&Msn61> for Msn61 {
    type Output = Msn61;
    fn mul(self, rhs: &Msn61) -> Self::Output {
        let vv = msn61_mod(self.v as u128 * rhs.v as u128);
        Msn61 {
            v: msn61_try_sub(vv),
        }
    }
}

impl Mul for Msn61 {
    type Output = Msn61;
    fn mul(self, rhs: Self) -> Self::Output {
        self * &rhs
    }
}

impl MulAssign<&Msn61> for Msn61 {
    fn mul_assign(&mut self, rhs: &Msn61) {
        *self = *self * rhs
    }
}

impl MulAssign for Msn61 {
    #[inline(always)]
    fn mul_assign(&mut self, rhs: Self) {
        *self *= &rhs;
    }
}

impl<T: ::core::borrow::Borrow<Msn61>> Product<T> for Msn61 {
    fn product<I: Iterator<Item = T>>(iter: I) -> Self {
        iter.fold(Self::one(), |acc, item| acc * item.borrow())
    }
}
