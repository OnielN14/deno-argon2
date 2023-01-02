use argon2::{
    hash_encoded, verify_encoded, verify_encoded_ext, Config, ThreadMode, Variant, Version,
};
use bytes::Bytes;
use serde::{Deserialize, Serialize};

#[cfg(feature = "deno")]
use deno_core::{plugin_api::Interface, Op, ZeroCopyBuf};

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::error::Error;

#[cfg(feature = "wasm")]
#[wasm_bindgen(typescript_custom_section)]
const JS_PARAMS_STYLE: &'static str = r#"
export interface IHashOptions {
    salt: Uint8Array;
    secret?: Uint8Array;
    data?: Uint8Array;
    version?: string;
    variant?: string;
    memoryCost?: number;
    timeCost?: number;
    lanes?: number;
    threadMode?: number;
    hashLength?: number;
}

export interface IHashParams {
    password: string;
    options: IHashOptions;
}

export interface IVerifyParams {
    password: string;
    hash: string;
}

export interface IVerifyParamsExt {
    verifyParams: IVerifyParams;
    secret: Uint8Array;
    data?: Uint8Array;
}
"#;

#[cfg(feature = "wasm")]
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "IHashParams")]
    pub type IHashParams;

    #[wasm_bindgen(typescript_type = "IVerifyParams")]
    pub type IVerifyParams;

    #[wasm_bindgen(typescript_type = "IVerifyParamsExt")]
    pub type IVerifyParamsExt;

    #[wasm_bindgen(js_namespace = console)]
    pub fn log(s: &str);
}

#[derive(Deserialize, Serialize)]
pub struct HashOptions {
    pub salt: Bytes,
    pub secret: Option<Bytes>,
    pub data: Option<Bytes>,
    pub version: Option<String>,
    pub variant: Option<String>,
    #[serde(rename(deserialize = "memoryCost"))]
    pub memory_cost: Option<u32>,
    #[serde(rename(deserialize = "timeCost"))]
    pub time_cost: Option<u32>,
    #[serde(rename(deserialize = "lanes"))]
    pub lanes: Option<u32>,
    #[serde(rename(deserialize = "threadMode"))]
    pub thread_mode: Option<u8>,
    #[serde(rename(deserialize = "hashLength"))]
    pub hash_length: Option<u32>,
}

#[derive(Deserialize, Serialize)]
pub struct HashParams {
    pub password: String,
    pub options: HashOptions,
}

#[derive(Deserialize, Serialize)]
pub struct VerifyParams {
    pub password: String,
    pub hash: String,
}

#[derive(Deserialize, Serialize)]
pub struct VerifyParamsExt {
    #[serde(rename(deserialize = "verifyParams"))]
    pub verify_params: VerifyParams,
    pub secret: Bytes,
    pub data: Option<Bytes>,
}

#[cfg(feature = "deno")]
pub fn hash(_interface: &mut dyn Interface, buffs: &mut [ZeroCopyBuf]) -> Op {
    let data = buffs[0].clone();
    let mut buf = buffs[1].clone();

    let params: HashParams =
        serde_json::from_slice(&data).expect("Unable parse data to HashParams");

    match hash_internal(params) {
        Ok(result) => {
            buf[0] = 1;
            Op::Sync(result.into_bytes().into_boxed_slice())
        }
        Err(err) => {
            error_handler(err, &mut buf);
            Op::Sync(Box::new([]))
        }
    }
}

#[cfg(feature = "deno")]
pub fn verify(_interface: &mut dyn Interface, buffs: &mut [ZeroCopyBuf]) -> Op {
    let data = buffs[0].clone();
    let mut buf = buffs[1].clone();

    let params: VerifyParams =
        serde_json::from_slice(&data).expect("Unable parse data to VerifyParams");

    match verify_internal(params) {
        Ok(result) => {
            buf[0] = 1;
            Op::Sync(Box::new([result as u8]))
        }
        Err(err) => {
            error_handler(err, &mut buf);
            Op::Sync(Box::new([]))
        }
    }
}

#[cfg(feature = "deno")]
fn error_handler(err: Error, buf: &mut ZeroCopyBuf) {
    buf[0] = 0;
    let e = format!("{}", err);
    let e = e.as_bytes();
    for (index, byte) in e.iter().enumerate() {
        buf[index + 1] = *byte;
    }
}

pub fn hash_internal(params: HashParams) -> Result<String, Error> {
    let salt = params.options.salt;

    let mut config: Config = Config::default();

    if let Some(ref secret) = params.options.secret {
        config.secret = &secret[..];
    }

    if let Some(ref data) = params.options.data {
        config.ad = &data[..];
    }

    if let Some(memory_cost) = params.options.memory_cost {
        config.mem_cost = memory_cost;
    }

    if let Some(time_cost) = params.options.time_cost {
        config.time_cost = time_cost;
    }

    if let Some(variant) = params.options.variant {
        if let Ok(v) = Variant::from_str(&variant) {
            config.variant = v;
        }
    }

    if let Some(version) = params.options.version {
        if let Ok(v) = Version::from_str(&version) {
            config.version = v;
        }
    }

    if let Some(lanes) = params.options.lanes {
        config.lanes = lanes;
    }

    if let Some(hash_length) = params.options.hash_length {
        config.hash_length = hash_length;
    }

    if let Some(thread_mode) = params.options.thread_mode {
        match thread_mode {
            0 => config.thread_mode = ThreadMode::Sequential,
            1 => config.thread_mode = ThreadMode::Parallel,
            _ => {}
        }
    }

    Ok(hash_encoded(&params.password.into_bytes(), &salt, &config)?)
}

pub fn verify_internal(options: VerifyParams) -> Result<bool, Error> {
    Ok(verify_encoded(
        &options.hash,
        &options.password.into_bytes(),
    )?)
}

pub fn verify_ext_internal(options: VerifyParamsExt) -> Result<bool, Error> {
    let ad = options.data.unwrap_or(Bytes::default());

    Ok(verify_encoded_ext(
        &options.verify_params.hash,
        options.verify_params.password.as_bytes(),
        &options.secret,
        &ad[..],
    )?)
}
