mod witness_calculator;
pub use witness_calculator::WitnessCalculator;

mod circom;
pub(super) use circom::{CircomBase, Wasm};

pub(super) use circom::Circom2;

use fnv::FnvHasher;
use std::hash::Hasher;

pub(crate) fn fnv(inp: &str) -> (u32, u32) {
    let mut hasher = FnvHasher::default();
    hasher.write(inp.as_bytes());
    let h = hasher.finish();

    ((h >> 32) as u32, h as u32)
}
