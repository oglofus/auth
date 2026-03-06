export interface UserBase {
  id: string;
  email: string;
  emailVerified: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export type RequireKeys<T, K extends keyof T> = T & { [P in K]-?: T[P] };

export type LocalProfileFields<U extends UserBase, K extends keyof U> = Pick<
  RequireKeys<U, K>,
  K
>;

export type PrimaryAuthMethod =
  | "password"
  | "email_otp"
  | "magic_link"
  | "oauth2"
  | "passkey";

export type AuthMethodName = PrimaryAuthMethod | (string & {});

export type SecondFactorMethod = "totp" | "recovery_code";

export type AccountDiscoveryMode = "private" | "explicit";

export type DiscoverIntent = "login" | "register";

export type SignInMethodHint = {
  method: AuthMethodName;
  provider?: string;
};

export type DiscoverAccountInput = {
  email: string;
  intent: DiscoverIntent;
  preferredMethod?: AuthMethodName;
  locale?: string;
};

export type DiscoverAccountDecision =
  | {
      action: "continue_login";
      reason: "ACCOUNT_FOUND";
      prefill: { email: string };
      suggestedMethods: SignInMethodHint[];
      messageKey?: string;
    }
  | {
      action: "redirect_register";
      reason: "ACCOUNT_NOT_FOUND";
      prefill: { email: string };
      messageKey: "auth.no_account";
    }
  | {
      action: "redirect_login";
      reason: "ACCOUNT_EXISTS";
      prefill: { email: string };
      suggestedMethods: SignInMethodHint[];
      messageKey: "auth.account_exists";
    }
  | {
      action: "continue_generic";
      reason: "DISCOVERY_PRIVATE";
      prefill: { email: string };
      messageKey: "auth.check_credentials_or_continue";
    };

export type PasswordAuthenticateInput = {
  method: "password";
  email: string;
  password: string;
};

export type PasswordRegisterInput<U extends UserBase, K extends keyof U> = {
  method: "password";
  email: string;
  password: string;
} & LocalProfileFields<U, K>;

export type EmailOtpAuthenticateInput = {
  method: "email_otp";
  challengeId: string;
  code: string;
};

export type EmailOtpRegisterInput<U extends UserBase, K extends keyof U> = {
  method: "email_otp";
  challengeId: string;
  code: string;
} & LocalProfileFields<U, K>;

export type MagicLinkAuthenticateInput = {
  method: "magic_link";
  token: string;
};

export type MagicLinkRegisterInput<U extends UserBase, K extends keyof U> = {
  method: "magic_link";
  token: string;
} & LocalProfileFields<U, K>;

export type OAuth2AuthenticateInput<P extends string> = {
  method: "oauth2";
  provider: P;
  authorizationCode: string;
  redirectUri: string;
  codeVerifier?: string;
  idempotencyKey?: string;
};

export type OAuth2RegisterInput<P extends string> = OAuth2AuthenticateInput<P>;

export type WebAuthnJson = Record<string, unknown>;

export type VerifiedPasskeyRegistration = {
  credentialId: string;
  publicKey: string;
  counter: number;
  transports?: string[];
};

export type VerifiedPasskeyAuthentication = {
  credentialId: string;
  nextCounter: number;
};

export type PasskeyAuthenticateInput = {
  method: "passkey";
  authentication: VerifiedPasskeyAuthentication;
};

export type PasskeyRegisterInput<U extends UserBase, K extends keyof U> = {
  method: "passkey";
  email: string;
  registration: VerifiedPasskeyRegistration;
} & LocalProfileFields<U, K>;

export type TwoFactorVerifyInput =
  | { method: "totp"; pendingAuthId: string; code: string }
  | { method: "recovery_code"; pendingAuthId: string; code: string };

export type ProfileCompletionState<U extends UserBase> = {
  pendingProfileId: string;
  sourceMethod: AuthMethodName;
  email?: string;
  missingFields: readonly Extract<keyof U, string>[];
  prefill: Partial<U>;
  continuation?: Record<string, unknown>;
};

export type CompleteProfileInput<U extends UserBase> = {
  pendingProfileId: string;
  profile: Partial<U>;
};

export interface OrganizationBase {
  id: string;
  slug: string;
  name: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface MembershipBase<Role extends string = string> {
  id: string;
  organizationId: string;
  userId: string;
  role: Role;
  status: "active" | "invited" | "suspended";
  createdAt: Date;
  updatedAt: Date;
}

export type OrganizationCustomFields<
  O extends OrganizationBase,
  K extends keyof O,
> = Pick<RequireKeys<O, K>, K>;

export type OrganizationRoleDefinition<
  Role extends string,
  Permission extends string,
  Feature extends string,
  LimitKey extends string,
> = {
  permissions: readonly Permission[];
  features?: Partial<Record<Feature, boolean>>;
  limits?: Partial<Record<LimitKey, number>>;
  inherits?: readonly Role[];
  system?: {
    owner?: boolean;
    default?: boolean;
  };
};

export type OrganizationRoleCatalog<
  Role extends string,
  Permission extends string,
  Feature extends string,
  LimitKey extends string,
> = Record<Role, OrganizationRoleDefinition<Role, Permission, Feature, LimitKey>>;

export type OrganizationEntitlementSnapshot<
  Feature extends string,
  LimitKey extends string,
> = {
  features: Partial<Record<Feature, boolean>>;
  limits: Partial<Record<LimitKey, number>>;
};

export interface AuthRequestContext {
  requestId?: string;
  ip?: string;
  userAgent?: string;
  userId?: string;
}

export interface RuntimeValidator<T> {
  parse(input: unknown): T;
}

export interface TwoFactorRequiredMeta {
  pendingAuthId: string;
  availableSecondFactors: SecondFactorMethod[];
}

export interface Session {
  id: string;
  userId: string;
  activeOrganizationId?: string;
  expiresAt: Date;
  createdAt: Date;
  revokedAt?: Date | null;
  rotatedFromSessionId?: string;
}
