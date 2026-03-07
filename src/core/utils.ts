import { createHash, pbkdf2Sync, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";

export const DEFAULT_SESSION_TTL_SECONDS = 60 * 60 * 24 * 30;

export const normalizeEmailDefault = (value: string): string => value.trim().toLowerCase();

export const now = (): Date => new Date();

export const addSeconds = (date: Date, seconds: number): Date => new Date(date.getTime() + seconds * 1_000);

export const createId = (): string => randomUUID();

export const createToken = (size = 32): string => randomBytes(size).toString("base64url");

export const createNumericCode = (length = 6): string => {
  const digits = "0123456789";
  let out = "";
  for (let i = 0; i < length; i += 1) {
    const idx = (randomBytes(1)[0] ?? 0) % digits.length;
    out += digits[idx] ?? "0";
  }
  return out;
};

export const secretHash = (value: string, salt = randomBytes(16).toString("hex")): string => {
  const derived = pbkdf2Sync(value, salt, 120_000, 32, "sha256").toString("hex");
  return `${salt}:${derived}`;
};

export const deterministicTokenHash = (value: string, namespace: string): string =>
  createHash("sha256").update(namespace).update(":").update(value).digest("hex");

export const secretVerify = (value: string, encoded: string): boolean => {
  const [salt, hash] = encoded.split(":");
  if (!salt || !hash) {
    return false;
  }

  const actual = pbkdf2Sync(value, salt, 120_000, 32, "sha256").toString("hex");
  const hashBuffer = Buffer.from(hash, "hex");
  const actualBuffer = Buffer.from(actual, "hex");

  if (hashBuffer.length !== actualBuffer.length) {
    return false;
  }

  return timingSafeEqual(hashBuffer, actualBuffer);
};

export const cloneWithout = <T extends Record<string, unknown>, K extends readonly (keyof T)[]>(
  input: T,
  keys: K,
): Omit<T, K[number]> => {
  const out: Partial<T> = { ...input };
  for (const key of keys) {
    delete out[key];
  }
  return out as Omit<T, K[number]>;
};

export const ensureRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null;

export const ensureString = (value: unknown): value is string => typeof value === "string" && value.length > 0;

export const isExpired = (at: Date, current: Date): boolean => at.getTime() <= current.getTime();
