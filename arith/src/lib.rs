// #![cfg_attr(target_arch = "x86_64", feature(stdarch_x86_avx512))]

pub mod field;
pub use field::*;

mod poly;
pub use poly::*;

pub mod mul_group;

#[cfg(test)]
mod tests;
