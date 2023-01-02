import { IVerifyParams, IVerifyParamsExt } from "../../pkg/deno_argon2.d.ts";
import { HashParams } from "../common.ts";

const dll = Deno.dlopen(
  "./target/release/deno_argon2.dll",
  {
    argon2_hash: {
      parameters: ["buffer"],
      result: "buffer",
    },
    free_argon2_hash: {
      parameters: ["pointer"],
      result: "void",
    },
    argon2_verify: {
      parameters: ["buffer"],
      result: "u8",
    },
    argon2_verify_ext: {
      parameters: ["buffer"],
      result: "u8",
    },
  } as const,
);

const encoder = new TextEncoder();

const stringToNulTerminatedBuffer = (value: string) =>
  encoder.encode(value + "\0");

const jsonToBuffer = (value: any) => {
  const stringifed = JSON.stringify(value, (_k, v) => {
    return ArrayBuffer.isView(v)
      ? Array.from(v as unknown as Iterable<unknown>)
      : v;
  });

  return stringToNulTerminatedBuffer(stringifed);
};

const hash = (params: HashParams) => {
  const paramsBuffer = jsonToBuffer(params);
  const pointer = dll.symbols.argon2_hash(paramsBuffer);

  const result = Deno.UnsafePointerView.getCString(pointer);
  dll.symbols.free_argon2_hash(pointer);
  return result;
};

const verify = (params: IVerifyParams) => {
  const paramsBuffer = jsonToBuffer(params);
  const matches = dll.symbols.argon2_verify(paramsBuffer);

  return matches;
};

const verifyExt = (params: IVerifyParamsExt) => {
  const paramsBuffer = jsonToBuffer(params);
  const matches = dll.symbols.argon2_verify_ext(paramsBuffer);

  return matches;
};

export { hash, jsonToBuffer, stringToNulTerminatedBuffer, verify, verifyExt };
