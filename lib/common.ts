export let MIN_SALT_SIZE = 8;

export enum Variant {
  Argon2i = "argon2i",
  Argon2d = "argon2d",
  Argon2id = "argon2id",
}

export enum Version {
  V10 = "16",
  V13 = "19",
}

export enum ThreadMode {
  Sequential,
  Parallel,
}

export interface HashOptions {
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

export interface HashParams {
  password: string;
  options: HashOptions;
}

export interface VerifyParams {
  password: string;
  hash: string;
}

export interface VerifyParamsExt {
  verifyParams: VerifyParams;
  secret: Uint8Array;
  data?: Uint8Array;
}

export function version() {
  return "0.10.0";
}
