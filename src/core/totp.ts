import { generateTOTP, verifyTOTPWithGracePeriod } from "@oslojs/otp";

const toKey = (secret: string): Uint8Array => Buffer.from(secret, "base64url");

const withNow = <T>(at: Date, run: () => T): T => {
  const originalNow = Date.now;
  Date.now = () => at.getTime();
  try {
    return run();
  } finally {
    Date.now = originalNow;
  }
};

export const generateTotp = (
  secret: string,
  at: Date,
  stepSeconds = 30,
  digits = 6,
): string => {
  return withNow(at, () => generateTOTP(toKey(secret), stepSeconds, digits));
};

export const verifyTotp = (
  secret: string,
  code: string,
  at: Date,
  window = 1,
  stepSeconds = 30,
  digits = 6,
): boolean => {
  const gracePeriodSeconds = Math.max(0, window) * stepSeconds;
  return withNow(at, () =>
    verifyTOTPWithGracePeriod(toKey(secret), stepSeconds, digits, code, gracePeriodSeconds),
  );
};
