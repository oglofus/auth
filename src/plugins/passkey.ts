import { AuthError } from "../errors/index.js";
import { createIssue } from "../issues/index.js";
import type { PasskeyAdapter } from "../types/adapters.js";
import type {
  PasskeyAuthenticateInput,
  PasskeyRegisterInput,
  UserBase,
  WebAuthnJson,
} from "../types/model.js";
import type { AuthMethodPlugin } from "../types/plugins.js";
import { errorOperation, successOperation } from "../types/results.js";
import { cloneWithout, createId } from "../core/utils.js";
import { ensureFields } from "../core/validators.js";

export type PasskeyPluginConfig<U extends UserBase, K extends keyof U> = {
  requiredProfileFields: readonly K[];
  passkeys: PasskeyAdapter;
};

const getString = (obj: WebAuthnJson, key: string): string | null => {
  const value = obj[key];
  return typeof value === "string" && value.length > 0 ? value : null;
};

const getNumber = (obj: WebAuthnJson, key: string): number | null => {
  const value = obj[key];
  return typeof value === "number" && Number.isFinite(value) ? value : null;
};

export const passkeyPlugin = <U extends UserBase, K extends keyof U>(
  config: PasskeyPluginConfig<U, K>,
): AuthMethodPlugin<
  "passkey",
  PasskeyRegisterInput<U, K>,
  PasskeyAuthenticateInput,
  U
> => ({
  kind: "auth_method",
  method: "passkey",
  version: "1.0.0",
  supports: {
    register: true,
  },
  issueFields: {
    authenticate: ["email", "assertion"],
    register: ["email", "attestation", ...config.requiredProfileFields.map(String)] as any,
  },
  authenticate: async (ctx, input) => {
    const credentialId = getString(input.assertion, "credentialId");
    if (!credentialId) {
      return errorOperation(
        new AuthError("PASSKEY_INVALID_ASSERTION", "Credential id missing from assertion.", 400, [
          createIssue("credentialId is required", ["assertion", "credentialId"]),
        ]),
      );
    }

    const credential = await config.passkeys.findByCredentialId(credentialId);
    if (!credential) {
      return errorOperation(
        new AuthError("PASSKEY_INVALID_ASSERTION", "Unknown passkey credential.", 400),
      );
    }

    const counter = getNumber(input.assertion, "counter");
    if (counter !== null) {
      if (counter <= credential.counter) {
        return errorOperation(
          new AuthError(
            "PASSKEY_INVALID_ASSERTION",
            "Passkey counter regression detected.",
            400,
          ),
        );
      }
      await config.passkeys.updateCounter(credential.credentialId, counter);
    }

    const user = await ctx.adapters.users.findById(credential.userId);
    if (!user) {
      return errorOperation(new AuthError("USER_NOT_FOUND", "User not found.", 404));
    }

    return successOperation({ user });
  },
  register: async (ctx, input) => {
    const requiredError = ensureFields(
      input as unknown as Record<string, unknown>,
      config.requiredProfileFields.map(String),
    );
    if (requiredError) {
      return errorOperation(requiredError);
    }

    const credentialId = getString(input.attestation, "credentialId");
    const publicKey = getString(input.attestation, "publicKey");
    const counter = getNumber(input.attestation, "counter") ?? 0;

    if (!credentialId || !publicKey) {
      return errorOperation(
        new AuthError("PASSKEY_INVALID_ATTESTATION", "Invalid passkey attestation.", 400, [
          createIssue("credentialId/publicKey is required", ["attestation"]),
        ]),
      );
    }

    let user = await ctx.adapters.users.findByEmail(input.email);
    if (!user) {
      const payload = cloneWithout(input as unknown as Record<string, unknown>, [
        "method",
        "attestation",
      ] as const);
      payload.emailVerified = true;

      user = await ctx.adapters.users.create(payload as Omit<U, "id" | "createdAt" | "updatedAt">);
    }

    await config.passkeys.create({
      id: createId(),
      userId: user.id,
      credentialId,
      publicKey,
      counter,
      createdAt: ctx.now(),
    });

    return successOperation({ user });
  },
});
