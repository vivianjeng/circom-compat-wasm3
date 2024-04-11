use super::{fnv, CircomBase, Wasm};
use color_eyre::Result;
use num_bigint::BigInt;
use num_traits::Zero;
use wasmer::{imports, Function, Instance, Memory, MemoryType, Module, RuntimeError, Store};

use num::ToPrimitive;

use super::Circom2;

#[derive(Clone, Debug)]
pub struct WitnessCalculator {
    pub instance: Wasm,
    pub n64: u32,
    pub circom_version: u32,
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
        let store = Store::default();
        let module = Module::from_file(&store, path)?;
        Self::from_module(module)
    }

    pub fn from_module(module: Module) -> Result<Self> {
        let store = module.store();

        // Set up the memory
        let memory = Memory::new(store, MemoryType::new(2000, None, false)).unwrap();
        let import_object = imports! {
            "env" => {
                "memory" => memory.clone(),
            },
            // Host function callbacks from the WASM
            "runtime" => {
                "error" => runtime::error(store),
                "exceptionHandler" => runtime::exception_handler(store),
                "showSharedRWMemory" => runtime::show_memory(store),
                "printErrorMessage" => runtime::print_error_message(store),
                "writeBufferMessage" => runtime::write_buffer_message(store),
            }
        };
        let instance = Wasm::new(Instance::new(&module, &import_object)?);

        let version = instance.get_version().unwrap_or(1);

        fn new_circom2(instance: Wasm, version: u32) -> Result<WitnessCalculator> {
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
                instance,
                n64,
                circom_version: version,
            })
        }
        new_circom2(instance, version)
    }

    pub fn calculate_witness<I: IntoIterator<Item = (String, Vec<BigInt>)>>(
        &mut self,
        inputs: I,
        sanity_check: bool,
    ) -> Result<Vec<BigInt>> {
        self.instance.init(sanity_check)?;

        self.calculate_witness_circom2(inputs, sanity_check)
    }

    fn calculate_witness_circom2<I: IntoIterator<Item = (String, Vec<BigInt>)>>(
        &mut self,
        inputs: I,
        sanity_check: bool,
    ) -> Result<Vec<BigInt>> {
        self.instance.init(sanity_check)?;

        let n32 = self.instance.get_field_num_len32()?;

        // allocate the inputs
        for (name, values) in inputs.into_iter() {
            let (msb, lsb) = fnv(&name);

            for (i, value) in values.into_iter().enumerate() {
                let f_arr = to_array32(&value, n32 as usize);
                for j in 0..n32 {
                    self.instance
                        .write_shared_rw_memory(j, f_arr[(n32 as usize) - 1 - (j as usize)])?;
                }
                self.instance.set_input_signal(msb, lsb, i as u32)?;
            }
        }

        let mut w = Vec::new();

        let witness_size = self.instance.get_witness_size()?;
        for i in 0..witness_size {
            self.instance.get_witness(i)?;
            let mut arr = vec![0; n32 as usize];
            for j in 0..n32 {
                arr[(n32 as usize) - 1 - (j as usize)] = self.instance.read_shared_rw_memory(j)?;
            }
            w.push(from_array32(arr));
        }

        Ok(w)
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
        let witness = self.calculate_witness(inputs, sanity_check)?;
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
mod runtime {
    use super::*;

    pub fn error(store: &Store) -> Function {
        #[allow(unused)]
        #[allow(clippy::many_single_char_names)]
        fn func(a: i32, b: i32, c: i32, d: i32, e: i32, f: i32) -> Result<(), RuntimeError> {
            // NOTE: We can also get more information why it is failing, see p2str etc here:
            // https://github.com/iden3/circom_runtime/blob/master/js/witness_calculator.js#L52-L64
            println!("runtime error, exiting early: {a} {b} {c} {d} {e} {f}",);
            Err(RuntimeError::user(Box::new(ExitCode(1))))
        }
        Function::new_native(store, func)
    }

    // Circom 2.0
    pub fn exception_handler(store: &Store) -> Function {
        #[allow(unused)]
        fn func(a: i32) {}
        Function::new_native(store, func)
    }

    // Circom 2.0
    pub fn show_memory(store: &Store) -> Function {
        #[allow(unused)]
        fn func() {}
        Function::new_native(store, func)
    }

    // Circom 2.0
    pub fn print_error_message(store: &Store) -> Function {
        #[allow(unused)]
        fn func() {}
        Function::new_native(store, func)
    }

    // Circom 2.0
    pub fn write_buffer_message(store: &Store) -> Function {
        #[allow(unused)]
        fn func() {}
        Function::new_native(store, func)
    }
}
