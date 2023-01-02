use command::{
    hash_internal, verify_ext_internal, verify_internal, HashParams, VerifyParams, VerifyParamsExt,
};

#[cfg(feature = "wasm")]
use command::{IHashParams, IVerifyParams, IVerifyParamsExt};

#[cfg(feature = "wasm")]
use serde_wasm_bindgen::from_value;

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

mod command;
mod error;

#[cfg(feature = "deno")]
use deno_core::plugin_api::Interface;

#[cfg(feature = "deno")]
#[no_mangle]
fn deno_plugin_init(context: &mut dyn Interface) {
    context.register_op("argon2_hash", command::hash);
    context.register_op("argon2_verify", command::verify);
}

#[cfg(feature = "wasm")]
#[wasm_bindgen(js_name = "argon2_hash")]
pub fn argon2_hash_wasm(params: IHashParams) -> String {
    let params: JsValue = params.into();
    let params: HashParams = from_value(params).unwrap();

    let result = match hash_internal(params) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("{err}");
            "".to_string()
        }
    };

    return result;
}

#[cfg(feature = "wasm")]
#[wasm_bindgen(js_name = "argon2_verify")]
pub fn argon2_verify_wasm(val: IVerifyParams) -> bool {
    let params: JsValue = val.into();
    let params: VerifyParams = from_value(params).unwrap();

    match verify_internal(params) {
        Ok(value) => value,
        Err(_err) => false,
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen(js_name = "argon2_verify_ext")]
pub fn argon2_verify_ext_wasm(params: IVerifyParamsExt) -> bool {
    let params: JsValue = params.into();
    let params: VerifyParamsExt = from_value(params).unwrap();

    match verify_ext_internal(params) {
        Ok(value) => value,
        Err(_err) => false,
    }
}

#[cfg(feature = "default")]
fn ptr_to_serde_json<'a, T: serde::Deserialize<'a>>(ptr: *const i8) -> serde_json::Result<T> {
    use std::ffi::CStr;

    let payload_str: &str = unsafe {
        assert!(!ptr.is_null());

        CStr::from_ptr(ptr).to_str().unwrap()
    };

    Ok(serde_json::from_str::<T>(payload_str)?)
}

#[cfg(feature = "default")]
#[no_mangle]
pub extern "C" fn argon2_hash(ptr: *const i8) -> *const i8 {
    use std::ffi::CString;

    let params: HashParams = ptr_to_serde_json(ptr).unwrap();
    let result = match hash_internal(params) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("{err}");
            "".to_string()
        }
    };

    let c_string = CString::new(result).unwrap();
    return c_string.into_raw();
}

#[cfg(feature = "default")]
#[no_mangle]
pub extern "C" fn free_argon2_hash(ptr: *mut i8) {
    use std::ffi::CString;

    unsafe {
        if ptr.is_null() {
            return;
        }

        let _ = CString::from_raw(ptr);
    }
}

#[cfg(feature = "default")]
#[no_mangle]
pub extern "C" fn argon2_verify(ptr: *const i8) -> u8 {
    let params: VerifyParams = ptr_to_serde_json(ptr).unwrap();
    let result = verify_internal(params).unwrap_or(false);

    result as u8
}

#[cfg(feature = "default")]
#[no_mangle]
pub extern "C" fn argon2_verify_ext(ptr: *const i8) -> u8 {
    let params: VerifyParamsExt = ptr_to_serde_json(ptr).unwrap();
    let result = verify_ext_internal(params).unwrap_or(false);

    result as u8
}
