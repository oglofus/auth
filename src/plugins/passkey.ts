import { AuthError } from "../errors/index.js";
import { createIssue } from "../issues/index.js";
import type { PasskeyAdapter } from "../types/adapters.js";
import type {
  PasskeyAuthenticateInput,
  PasskeyRegisterInput,
  UserBase,
} from "../types/model.js";
import type { AuthMethodPlugin } from "../types/plugins.js";
import { errorOperation, successOperation } from "../types/results.js";
import { cloneWithout, createId } from "../core/utils.js";
import { ensureFields } from "../core/validators.js";

export type PasskeyPluginConfig<U extends UserBase, K extends keyof U> = {
  requiredProfileFields: readonly K[];
  passkeys: PasskeyAdapter;
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
  version: "2.0.0",
  supports: {
    register: true,
  },
  issueFields: {
    authenticate: ["authentication"],
    register: ["email", "registration", ...config.requiredProfileFields.map(String)] as any,
  },
  authenticate: async (ctx, input) => {
    const credentialId = input.authentication.credentialId;
    if (!credentialId) {
      return errorOperation(
        new AuthError("PASSKEY_INVALID_ASSERTION", "Credential id missing from verified passkey authentication.", 400, [
          createIssue("credentialId is required", ["authentication", "credentialId"]),
        ]),
      );
    }

    const credential = await config.passkeys.findByCredentialId(credentialId);
    if (!credential) {
      return errorOperation(
        new AuthError("PASSKEY_INVALID_ASSERTION", "Unknown passkey credential.", 400),
      );
    }

    if (input.authentication.nextCounter <= credential.counter) {
      return errorOperation(
        new AuthError(
          "PASSKEY_INVALID_ASSERTION",
          "Passkey counter regression detected.",
          400,
        ),
      );
    }

    await config.passkeys.updateCounter(credential.credentialId, input.authentication.nextCounter);

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

    const { credentialId, publicKey, counter, transports } = input.registration;

    if (!credentialId || !publicKey) {
      return errorOperation(
        new AuthError("PASSKEY_INVALID_ATTESTATION", "Invalid verified passkey registration.", 400, [
          createIssue("credentialId/publicKey is required", ["registration"]),
        ]),
      );
    }

    const existingCredential = await config.passkeys.findByCredentialId(credentialId);
    if (existingCredential) {
      return errorOperation(
        new AuthError("CONFLICT", "Passkey credential already exists.", 409, [
          createIssue("credentialId already registered", ["registration", "credentialId"]),
        ]),
      );
    }

    let user = await ctx.adapters.users.findByEmail(input.email);
    if (!user) {
      const payload = cloneWithout(input as unknown as Record<string, unknown>, [
        "method",
        "registration",
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
      transports,
      createdAt: ctx.now(),
    });

    return successOperation({ user });
  },
});
