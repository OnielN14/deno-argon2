import { HashParams, VerifyParamsExt } from "./lib/common.ts";
import { hash, stringToNulTerminatedBuffer, verifyExt } from "./lib/ffi/mod.ts";

const salt = crypto.getRandomValues(new Uint8Array(10));
const password = "12345";
const secretStr = "this-is-a-secret";
const secret = stringToNulTerminatedBuffer(secretStr);

const hashParamsJson: HashParams = {
  options: {
    salt,
    secret,
  },
  password,
};

const hashResult = hash(hashParamsJson);

console.log(hashResult);
const verifyParamJson: VerifyParamsExt = {
  secret,
  verifyParams: { hash: hashResult, password },
};
const matches = verifyExt(verifyParamJson);

console.log(Boolean(matches));
