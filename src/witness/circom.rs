use color_eyre::Result;
use wasm3::Module;
pub struct Wasm<'a>(pub Module<'a>);

pub trait CircomBase {
    fn init(&self, sanity_check: bool) -> Result<()>;
    fn get_u32(&self, name: &str) -> Result<u32>;
    // Only exists natively in Circom2, hardcoded for Circom
    fn get_version(&self) -> Result<u32>;
}

pub trait Circom2 {
    fn get_field_num_len32(&self) -> Result<u32>;
    fn get_raw_prime(&self) -> Result<()>;
    fn read_shared_rw_memory(&self, i: u32) -> Result<u32>;
    fn write_shared_rw_memory(&self, i: u32, v: u32) -> Result<()>;
    fn set_input_signal(&self, hmsb: u32, hlsb: u32, pos: u32) -> Result<()>;
    fn get_witness(&self, i: u32) -> Result<()>;
    fn get_witness_size(&self) -> Result<u32>;
}

impl<'a> Circom2 for Wasm<'a> {
    fn get_field_num_len32(&self) -> Result<u32> {
        self.get_u32("getFieldNumLen32")
    }

    fn get_raw_prime(&self) -> Result<()> {
        let func = self
            .0
            .find_function::<(), ()>("getRawPrime")
            .expect("Unable to find function");
        func.call().unwrap();
        Ok(())
    }

    fn read_shared_rw_memory(&self, i: u32) -> Result<u32> {
        let func = self
            .0
            .find_function::<i32, i32>("readSharedRWMemory")
            .expect("Unable to find function");
        let result = func.call(i as i32).unwrap();
        Ok(result as u32)
    }

    fn write_shared_rw_memory(&self, i: u32, v: u32) -> Result<()> {
        let func = self
            .0
            .find_function::<(i32, i32), ()>("writeSharedRWMemory")
            .expect("Unable to find function");
        func.call(i as i32, v as i32).unwrap();
        Ok(())
    }

    fn set_input_signal(&self, hmsb: u32, hlsb: u32, pos: u32) -> Result<()> {
        let func = self
            .0
            .find_function::<(i32, i32, i32), ()>("setInputSignal")
            .expect("Unable to find function");
        let _ = func.call(hmsb as i32, hlsb as i32, pos as i32);
        Ok(())
    }

    fn get_witness(&self, i: u32) -> Result<()> {
        let func = self
            .0
            .find_function::<i32, ()>("getWitness")
            .expect("Unable to find function");
        func.call(i as i32).unwrap();
        Ok(())
    }

    fn get_witness_size(&self) -> Result<u32> {
        self.get_u32("getWitnessSize")
    }
}

impl<'a> CircomBase for Wasm<'a> {
    fn init(&self, sanity_check: bool) -> Result<()> {
        let func = self
            .0
            .find_function::<i32, ()>("init")
            .expect("Unable to find function");
        func.call(sanity_check as i32).unwrap();
        Ok(())
    }

    fn get_version(&self) -> Result<u32> {
        match self.0.find_function::<(), i32>("getVersion") {
            Ok(func) => Ok(func.call().unwrap() as u32),
            Err(_) => Ok(1),
        }
    }

    fn get_u32(&self, name: &str) -> Result<u32> {
        let func = self
            .0
            .find_function::<(), i32>(name)
            .expect("Unable to find function");
        let result = func.call().unwrap();
        Ok(result as u32)
    }
}

impl<'a> Wasm<'a> {
    pub fn new(instance: Module<'a>) -> Wasm<'a> {
        Self(instance)
    }
}
