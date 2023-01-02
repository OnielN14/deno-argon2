// @deno-types="./pkg/deno_argon2.d.ts"
import init, {
  argon2_hash,
  argon2_verify,
  argon2_verify_ext,
} from "./pkg/deno_argon2.js";

await init();
const salt = crypto.getRandomValues(
  new Uint8Array(20),
);
const password = "test";
const secretStr = "a_secret";
const additionalDataStr = "additional_data";
const encoder = new TextEncoder();

const secret = encoder.encode(secretStr);
const additionalData = encoder.encode(additionalDataStr);

const hash = argon2_hash({
  options: {
    salt,
    data: additionalData,
    secret,
  },
  password,
});

console.log(`hash : ${hash}`);

const verifyResult = argon2_verify_ext({
  verifyParams: {
    hash,
    password,
  },
  secret,
});

console.log(`verify result : ${verifyResult}`);
