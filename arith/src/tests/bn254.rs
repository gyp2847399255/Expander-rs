use crate::FieldSerde;
use halo2curves::bn256::Fr;

use super::field::{
    fft_field_tests, random_field_tests, random_inversion_tests, random_serdes_tests,
    random_small_field_tests, test_basic_field_op,
};

#[test]
fn test_field() {
    random_field_tests::<Fr>("bn254::Fr".to_string());
    random_inversion_tests::<Fr>("bn254::Fr".to_string());
    random_small_field_tests::<Fr>("bn254::Fr".to_string());

    random_serdes_tests::<Fr>("Vectorized M31".to_string());
}

#[test]
fn test_bn254_basic_field_op() {
    test_basic_field_op::<Fr>();
}

#[test]
fn test_packed_bn254_basic_field_op() {
    test_basic_field_op::<Fr>();
}

#[test]
fn test_vectorize_bn254_basic_field_op() {
    test_basic_field_op::<Fr>();
}

#[test]
fn test_vectorize_bn254_root() {
    fft_field_tests::<Fr>();
}

#[test]
fn test_custom_serde_vectorize_bn254() {
    let a = Fr::from(256u32 + 2);
    let mut buffer = vec![Fr::default(); 1];
    let buffer_slice: &mut [u8] = unsafe {
        std::slice::from_raw_parts_mut(
            buffer.as_mut_ptr() as *mut u8,
            buffer.len() * std::mem::size_of::<Fr>(),
        )
    };
    a.serialize_into(buffer_slice);
    let b = Fr::deserialize_from(&buffer_slice);
    assert_eq!(a, b);
}
