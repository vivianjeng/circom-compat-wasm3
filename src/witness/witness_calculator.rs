use super::{fnv, CircomBase, Wasm};
use color_eyre::Result;
use num_bigint::BigInt;
use num_traits::Zero;

use num::ToPrimitive;
use wasm3::{Environment, Module};

use super::Circom2;

#[derive(Clone, Debug)]
pub struct WitnessCalculator {
    pub data: Vec<u8>,
    pub n64: u32,
}

// Error type to signal end of execution.
// From https://docs.wasmer.io/integrations/examples/exit-early
#[derive(thiserror::Error, Debug, Clone, Copy)]
#[error("{0}")]
struct ExitCode(u32);

fn from_array32(arr: Vec<u32>) -> BigInt {
    let mut res = BigInt::zero();
    let radix = BigInt::from(0x100000000u64);
    for &val in arr.iter() {
        res = res * &radix + BigInt::from(val);
    }
    res
}

fn to_array32(s: &BigInt, size: usize) -> Vec<u32> {
    let mut res = vec![0; size];
    let mut rem = s.clone();
    let radix = BigInt::from(0x100000000u64);
    let mut c = size;
    while !rem.is_zero() {
        c -= 1;
        res[c] = (&rem % &radix).to_u32().unwrap();
        rem /= &radix;
    }

    res
}

impl WitnessCalculator {
    pub fn new(path: impl AsRef<std::path::Path>) -> Result<Self> {
        Self::from_file(path)
    }

    pub fn from_file(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let data = std::fs::read(path).expect("Unable to read file");
        Self::from_bytes(&data)
    }

    pub fn from_bytes(data: &Vec<u8>) -> Result<Self> {
        let env = Environment::new().expect("Unable to create environment");
        let rt = env
            .create_runtime(1024 * 1024 * 1024)
            .expect("Unable to create runtime");
        let module = Module::parse(&env, &data[..]).expect("Unable to parse module");

        let module = rt.load_module(module).expect("Unable to load module");
        let instance = Wasm::new(module);
        let n32 = instance.get_field_num_len32()?;
        instance.get_raw_prime()?;
        let mut arr = vec![0; n32 as usize];
        for i in 0..n32 {
            let res = instance.read_shared_rw_memory(i)?;
            arr[(n32 as usize) - (i as usize) - 1] = res;
        }
        let prime = from_array32(arr);

        let n64 = ((prime.bits() - 1) / 64 + 1) as u32;

        Ok(WitnessCalculator {
            data: data.clone(),
            n64,
        })
    }

    pub fn calculate_witness_element<
        E: ark_ec::pairing::Pairing,
        I: IntoIterator<Item = (String, Vec<BigInt>)>,
    >(
        &mut self,
        inputs: I,
        sanity_check: bool,
    ) -> Result<Vec<E::ScalarField>> {
        use ark_ff::PrimeField;
        let env = Environment::new().expect("Unable to create environment");
        let rt = env
            .create_runtime(1024 * 1000000)
            .expect("Unable to create runtime");

        let module = Module::parse(&env, &self.data[..]).expect("Unable to parse module");

        let mut module = rt.load_module(module).expect("Unable to load module");
        module
            .link_function::<i32, ()>("runtime", "exceptionHandler", exception_handler_wrap)
            .expect("Failed to link runtime.exceptionHandler");

        // Link printErrorMessage function
        module
            .link_function::<(), ()>("runtime", "printErrorMessage", print_error_message_wrap)
            .expect("Failed to link runtime.printErrorMessage");

        // Link writeBufferMessage function
        module
            .link_function::<(), ()>("runtime", "writeBufferMessage", write_buffer_message_wrap)
            .expect("Failed to link runtime.writeBufferMessage");

        // Link showSharedRWMemory function
        module
            .link_function::<(), ()>("runtime", "showSharedRWMemory", show_shared_rw_memory_wrap)
            .expect("Failed to link runtime.showSharedRWMemory");
        let instance = Wasm::new(module);
        instance.init(sanity_check)?;

        let n32 = instance.get_field_num_len32()?;

        // allocate the inputs
        for (name, values) in inputs.into_iter() {
            let (msb, lsb) = fnv(&name);

            for (i, value) in values.into_iter().enumerate() {
                let f_arr = to_array32(&value, n32 as usize);
                for j in 0..n32 {
                    instance.write_shared_rw_memory(j, f_arr[(n32 as usize) - 1 - (j as usize)])?;
                }
                instance.set_input_signal(msb, lsb, i as u32)?;
            }
        }

        let mut witness = Vec::new();

        let witness_size = instance.get_witness_size()?;
        for i in 0..witness_size {
            instance.get_witness(i)?;
            let mut arr = vec![0; n32 as usize];
            for j in 0..n32 {
                arr[(n32 as usize) - 1 - (j as usize)] = instance.read_shared_rw_memory(j)?;
            }
            witness.push(from_array32(arr));
        }

        let modulus = <E::ScalarField as PrimeField>::MODULUS;

        // convert it to field elements
        use num_traits::Signed;
        let witness = witness
            .into_iter()
            .map(|w| {
                let w = if w.sign() == num_bigint::Sign::Minus {
                    // Need to negate the witness element if negative
                    modulus.into() - w.abs().to_biguint().unwrap()
                } else {
                    w.to_biguint().unwrap()
                };
                E::ScalarField::from(w)
            })
            .collect::<Vec<_>>();

        Ok(witness)
    }
}

// callback hooks for debugging
wasm3::make_func_wrapper!(
    exception_handler_wrap: exception_handler(_arg: i32) -> ()
);
fn exception_handler(_arg: i32) {
    // Implementation for runtime.exceptionHandler
    // You can handle exceptions here
}
wasm3::make_func_wrapper!(
    print_error_message_wrap: print_error_message() -> ()
);
fn print_error_message() {
    // Implementation for runtime.printErrorMessage
    println!("Error message printed from Rust");
}
wasm3::make_func_wrapper!(
    write_buffer_message_wrap: write_buffer_message() -> ()
);
fn write_buffer_message() {
    // Implementation for runtime.writeBufferMessage
    println!("Buffer message written from Rust");
}
wasm3::make_func_wrapper!(
    show_shared_rw_memory_wrap: show_shared_rw_memory() -> ()
);
fn show_shared_rw_memory() {
    // Implementation for runtime.showSharedRWMemory
    println!("Shared read-write memory shown from Rust");
}
