use crate::Msn61;

use super::field::{
    random_field_tests, random_inversion_tests, random_serdes_tests, random_small_field_tests,
};

#[test]
fn test_field() {
    random_field_tests::<Msn61>("Mersenne_61".to_string());
    random_inversion_tests::<Msn61>("Mersenne_61".to_string());
    random_small_field_tests::<Msn61>("Mersenne_61".to_string());
    random_serdes_tests::<Msn61>("Mersenne_61".to_string());
}
