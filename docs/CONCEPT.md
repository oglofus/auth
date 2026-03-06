# Oglofus Auth Concept - v1

## 1. Goal

Build a TypeScript authentication library that is:

- Database-agnostic (user provides storage adapters).
- Strongly typed across all auth flows.
- Extensible via events, without making core auth behavior non-deterministic.
- Composable (developers enable only the auth methods they want).

## 2. Non-goals (v1)

- No ORM, migrations, or built-in database.
- No UI components.
- No app-wide generic RBAC/ABAC engine in core (authorization policy stays app-specific).
- No opaque "magic" state machines hidden from the developer.

## 3. Core principles

- Core auth flow is deterministic.
- Events are extension points, not required to make auth work.
- Storage APIs are domain-oriented, not generic key-value only.
- Every public method returns a typed success/error contract.
- Enabled auth methods define valid input/output types.
- Compile-time typing is mirrored by runtime validation and normalization.
- Validation failures are path-addressable (field-level and nested payload-level issues).
- Sessions are issued only after all required factors pass (never before 2FA completion).
- Account discovery behavior is explicit and configurable (`private` vs `explicit`) per app risk posture.
- Multi-tenant boundaries must be explicit in API and enforced at authorization time.

## 4. Plugins in scope (plugin-first)

Core package does not bake auth methods directly into `OglofusAuth`.
Instead, it provides orchestration + typing + lifecycle, and auth methods are plugins.

Official plugins for v1:

- `password`
- `email_otp`
- `magic_link`
- `oauth2` (`google`, `apple`, `meta`, configurable)
- `passkey` (WebAuthn)
- `two_factor` (policy + second-factor verification)
- `organizations` (multi-tenant domain plugin for memberships, roles, features, and limits)

Plugin kinds:

- Auth-method plugins: participate in `authenticate(...)` and optionally `register(...)` (`password`, `oauth2`, `passkey`, etc.).
- Domain/policy plugins: expose APIs and cross-cutting policy, but are not direct login methods (`two_factor`, `organizations`).

Composition rule:

- Any primary method plugin (`password`, `magic_link`, `oauth2`, `passkey`, etc.) can be gated by `two_factor` policy.
- `organizations` is a domain plugin (authorization/tenancy), not a sign-in method.

Custom plugins:

- Developers can implement their own methods/domains (for example `enterprise_sso`, `saml`, `custom_hardware_token`) by implementing the plugin contracts.

Out of scope for official v1 plugins (candidate v2):

- SMS OTP (depends on messaging provider integration)
- Adaptive risk engine (device reputation, anomaly detection, dynamic step-up)

## 5. Type model

```ts
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

export type SecondFactorMethod =
  | "totp"
  | "email_otp"
  | "passkey"
  | "recovery_code";

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
      // for `private` mode to reduce account enumeration risk
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
};

export type OAuth2RegisterInput<P extends string> = OAuth2AuthenticateInput<P>;

// Keep this intentionally generic to avoid coupling core to specific WebAuthn helper libs.
export type WebAuthnJson = Record<string, unknown>;

export type PasskeyAuthenticateInput = {
  method: "passkey";
  email?: string;
  assertion: WebAuthnJson;
};

export type PasskeyRegisterInput<U extends UserBase, K extends keyof U> = {
  method: "passkey";
  email: string;
  attestation: WebAuthnJson;
} & LocalProfileFields<U, K>;

export type TwoFactorVerifyInput =
  | { method: "totp"; pendingAuthId: string; code: string }
  | { method: "email_otp"; pendingAuthId: string; code: string }
  | { method: "passkey"; pendingAuthId: string; assertion: WebAuthnJson }
  | { method: "recovery_code"; pendingAuthId: string; code: string };

export type ProfileCompletionState<U extends UserBase> = {
  pendingProfileId: string;
  sourceMethod: "oauth2" | "passkey";
  email?: string;
  missingFields: readonly Extract<keyof U, string>[];
  prefill: Partial<U>;
};

export type CompleteProfileInput<U extends UserBase> = {
  pendingProfileId: string;
  // Must satisfy all `missingFields` from pending profile state.
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
> = Record<
  Role,
  OrganizationRoleDefinition<Role, Permission, Feature, LimitKey>
>;

export type OrganizationEntitlementSnapshot<
  Feature extends string,
  LimitKey extends string,
> = {
  features: Partial<Record<Feature, boolean>>;
  limits: Partial<Record<LimitKey, number>>;
};
```

### Local profile fields are developer-defined and type-enforced

The local plugins (`password`, `email_otp`) accept `requiredProfileFields` as a generic tuple.
Those fields become required in local register input at compile time.

```ts
// K is inferred from requiredProfileFields
passwordPlugin<User, "given_name" | "family_name">({
  requiredProfileFields: ["given_name", "family_name"] as const,
  // ...
});
```

If a developer registers via local auth without those fields, TypeScript fails.
Plugins should also validate the same fields at runtime for non-TypeScript callers.

### Organization fields are also developer-defined

`organizations` plugin requires core fields from `OrganizationBase` and `MembershipBase`,
while additional organization/member fields remain developer-defined and typed.

```ts
interface Organization extends OrganizationBase {
  billing_email: string;
  tax_id?: string;
  industry?: "saas" | "agency" | "ecommerce";
}
```

Like local profile fields, `organizationRequiredFields` should be reflected in TypeScript input constraints
for `createOrganization(...)` and validated again at runtime.

### Two-factor flow model

Primary authentication plugins can return a `TWO_FACTOR_REQUIRED` error with:

- `pendingAuthId` (short-lived challenge ID)
- `availableSecondFactors` (for example `["totp", "passkey", "recovery_code"]`)

The client then calls `verifySecondFactor(...)` with `TwoFactorVerifyInput`.

### Path-based issues (drizzle-events style)

Auth operations should expose path-based issues so plugin failures can point to exact input locations:

- Top-level field: `["email"]`
- Nested value: `["assertion", "response", "clientDataJSON"]`
- Array item: `["factors", { index: 1 }, "code"]`

Example:

```ts
event.cancel(
  event.issue.email("Invalid email format"),
  event.issue.$path(
    ["assertion", "response", "signature"],
    "Invalid passkey signature",
  ),
);
```

### Plugin contracts and input inference

```ts
export interface AuthRequestContext {
  requestId?: string;
  ip?: string;
  userAgent?: string;
}

export interface RuntimeValidator<T> {
  parse(input: unknown): T;
}

export interface TwoFactorRequiredMeta {
  pendingAuthId: string;
  availableSecondFactors: SecondFactorMethod[];
}

export interface AuthPluginContext<U extends UserBase> {
  adapters: CoreAdapters<U>;
  now(): Date;
  request?: AuthRequestContext;
}

export interface BasePlugin<
  Method extends string,
  U extends UserBase,
  ExposedApi extends object = {},
> {
  kind: "auth_method" | "domain";
  method: Method;
  version: string;
  createApi?: (ctx: Omit<AuthPluginContext<U>, "request">) => ExposedApi;
}

export interface AuthMethodPlugin<
  Method extends string,
  RegisterInput extends { method: Method },
  AuthenticateInput extends { method: Method },
  U extends UserBase,
  ExposedApi extends object = {},
> extends BasePlugin<Method, U, ExposedApi> {
  kind: "auth_method";
  supports: {
    register: boolean;
  };
  validators?: {
    authenticate: RuntimeValidator<AuthenticateInput>;
    register?: RuntimeValidator<RegisterInput>;
  };
  // Helps make `event.issue.<field>()` type-safe and aligned with runtime payloads.
  issueFields?: {
    authenticate: readonly Extract<keyof AuthenticateInput, string>[];
    register?: readonly Extract<keyof RegisterInput, string>[];
  };
  register?: (
    ctx: AuthPluginContext<U>,
    input: RegisterInput,
  ) => Promise<AuthResult<U>>;
  authenticate: (
    ctx: AuthPluginContext<U>,
    input: AuthenticateInput,
  ) => Promise<AuthResult<U>>;
}

export interface DomainPlugin<
  Method extends string,
  U extends UserBase,
  ExposedApi extends object = {},
> extends BasePlugin<Method, U, ExposedApi> {
  kind: "domain";
}

export interface TwoFactorPluginApi<U extends UserBase> {
  verify(
    input: TwoFactorVerifyInput,
    request?: AuthRequestContext,
  ): Promise<AuthResult<U>>;
  beginTotpEnrollment(
    userId: string,
  ): Promise<OperationResult<{ enrollmentId: string; otpauthUri: string }>>;
  confirmTotpEnrollment(input: {
    enrollmentId: string;
    code: string;
  }): Promise<OperationResult<{ enabled: true }>>;
  regenerateRecoveryCodes(
    userId: string,
  ): Promise<OperationResult<{ codes: string[] }>>;
}

export interface EmailOtpPluginApi {
  request(
    input: { email: string; locale?: string },
    request?: AuthRequestContext,
  ): Promise<
    OperationResult<{ disposition: "sent" | "queued"; challengeId: string }>
  >;
}

export interface MagicLinkPluginApi {
  request(
    input: { email: string; redirectTo?: string; locale?: string },
    request?: AuthRequestContext,
  ): Promise<
    OperationResult<{ disposition: "sent" | "queued"; tokenId: string }>
  >;
}

export interface OrganizationsPluginApi<
  O extends OrganizationBase,
  Role extends string,
  M extends MembershipBase<Role>,
  Permission extends string,
  Feature extends string,
  LimitKey extends string,
  RequiredOrgFields extends keyof O = never,
> {
  createOrganization(
    input: {
      name: string;
      slug: string;
    } & ([RequiredOrgFields] extends [never]
      ? { profile?: Partial<O> }
      : { profile: Partial<O> & Pick<O, RequiredOrgFields> }),
    request?: AuthRequestContext,
  ): Promise<OperationResult<{ organization: O; membership: M }>>;
  inviteMember(
    input: {
      organizationId: string;
      email: string;
      role?: Role;
      locale?: string;
    },
    request?: AuthRequestContext,
  ): Promise<
    OperationResult<{ inviteId: string; disposition: "sent" | "queued" }>
  >;
  acceptInvite(
    input: { token: string; userId: string },
    request?: AuthRequestContext,
  ): Promise<OperationResult<{ organizationId: string; membership: M }>>;
  setActiveOrganization(
    input: { sessionId: string; organizationId?: string },
    request?: AuthRequestContext,
  ): Promise<
    OperationResult<{ sessionId: string; activeOrganizationId: string | null }>
  >;
  setMemberRole(
    input: { organizationId: string; membershipId: string; role: Role },
    request?: AuthRequestContext,
  ): Promise<OperationResult<{ membership: M }>>;
  listMemberships(
    input: { userId: string },
    request?: AuthRequestContext,
  ): Promise<OperationResult<{ memberships: M[] }>>;
  getEntitlements(
    input: { organizationId: string; userId: string },
    request?: AuthRequestContext,
  ): Promise<
    OperationResult<OrganizationEntitlementSnapshot<Feature, LimitKey>>
  >;
  setFeatureOverride(
    input: { organizationId: string; feature: Feature; enabled: boolean },
    request?: AuthRequestContext,
  ): Promise<
    OperationResult<{
      organizationId: string;
      feature: Feature;
      enabled: boolean;
    }>
  >;
  setLimitOverride(
    input: { organizationId: string; key: LimitKey; value: number },
    request?: AuthRequestContext,
  ): Promise<
    OperationResult<{ organizationId: string; key: LimitKey; value: number }>
  >;
  checkPermission(
    input: { organizationId: string; userId: string; permission: Permission },
    request?: AuthRequestContext,
  ): Promise<OperationResult<{ allowed: boolean; reason?: string }>>;
  checkFeature(
    input: { organizationId: string; userId: string; feature: Feature },
    request?: AuthRequestContext,
  ): Promise<OperationResult<{ enabled: boolean }>>;
  checkLimit(
    input: {
      organizationId: string;
      userId: string;
      key: LimitKey;
      amount?: number;
    },
    request?: AuthRequestContext,
  ): Promise<OperationResult<{ allowed: boolean; remaining?: number }>>;
}

export interface OrganizationsPluginConfig<
  O extends OrganizationBase,
  Role extends string,
  M extends MembershipBase<Role>,
  Permission extends string,
  Feature extends string,
  LimitKey extends string,
  RequiredOrgFields extends keyof O = never,
> {
  organizationRequiredFields?: readonly Extract<RequiredOrgFields, string>[];
  handlers: OrganizationsPluginHandlers<
    O,
    Role,
    M,
    Permission,
    Feature,
    LimitKey
  >;
}

type AnyMethodPlugin<U extends UserBase> = AuthMethodPlugin<
  string,
  any,
  any,
  U,
  any
>;
type AnyDomainPlugin<U extends UserBase> = DomainPlugin<string, U, any>;
type AnyPlugin<U extends UserBase> = AnyMethodPlugin<U> | AnyDomainPlugin<U>;

type MethodPlugins<P extends readonly AnyPlugin<any>[]> = Extract<
  P[number],
  AnyMethodPlugin<any>
>;

type RegisterInputFromPlugins<P extends readonly AnyPlugin<any>[]> =
  MethodPlugins<P> extends infer Pl
    ? Pl extends { supports: { register: true } }
      ? Pl extends AuthMethodPlugin<any, infer R, any, any, any>
        ? R
        : never
      : never
    : never;

type AuthenticateInputFromPlugins<P extends readonly AnyPlugin<any>[]> =
  MethodPlugins<P> extends AuthMethodPlugin<any, any, infer A, any, any>
    ? A
    : never;

type PluginApiMap<P extends readonly AnyPlugin<any>[]> = {
  [M in P[number]["method"]]: Extract<P[number], { method: M }> extends {
    createApi: (...args: any[]) => infer Api;
  }
    ? Api
    : never;
};

type PluginMethodsWithApi<P extends readonly AnyPlugin<any>[]> = {
  [M in keyof PluginApiMap<P>]: PluginApiMap<P>[M] extends never ? never : M;
}[keyof PluginApiMap<P>];

export interface AuthConfig<
  U extends UserBase,
  P extends readonly AnyPlugin<U>[],
> {
  adapters: CoreAdapters<U>;
  plugins: P;
  accountDiscovery?: {
    mode?: AccountDiscoveryMode; // default: "private"
  };
  normalize?: {
    email?: (value: string) => string;
  };
  validateConfigOnStart?: boolean;
}
```

Startup-time invariants:

- Plugin methods must be unique (`method` collision throws config error).
- Domain plugin methods (`two_factor`, `organizations`, etc.) must not collide with auth-method plugin methods.
- At most one `two_factor` policy plugin can be configured.
- At most one `organizations` plugin can be configured.
- For auth-method plugins, if `supports.register === true`, plugin must implement `register`.
- For auth-method plugins, if `supports.register === false`, plugin must not expose register-only payload paths.
- If `validators` are provided, they must cover all enabled operations.
- If `issueFields` are provided, they must match the operation payload shape used by that plugin.
- Out-of-band plugins (`email_otp`, `magic_link`) must configure delivery handlers.
- If `accountDiscovery.mode === "explicit"`, `identity` adapter must be configured.
- If `organizations` plugin is enabled, required organization/membership/invite adapters must be configured.
- If `organizations.organizationRequiredFields` is set, `createOrganization.profile` must provide those fields.
- Organization role catalog must have exactly one default role and at least one owner-capable role.
- Default role must not be owner-capable.
- `handlers.defaultRole` must exist in role catalog and match the role marked `system.default` (if provided).
- Role inheritance graphs must be acyclic.
- If seat limits are enabled, org membership creation must be atomic (via transaction wrapper or adapter-level atomic op).
- Core should normalize email (trim + lowercase by default) before plugin dispatch.

## 6. Storage adapters (DB-agnostic, domain-specific)

```ts
export type MaybeFound<T> = T | null | undefined;

export interface UserAdapter<U extends UserBase> {
  findById(id: string): Promise<MaybeFound<U>>;
  findByEmail(email: string): Promise<MaybeFound<U>>;
  create(input: Omit<U, "id" | "createdAt" | "updatedAt">): Promise<U>;
  update(id: string, patch: Partial<U>): Promise<MaybeFound<U>>;
}

export interface RateLimitResult {
  allowed: boolean;
  retryAfterSeconds?: number;
}

export interface RateLimiterAdapter {
  consume(
    key: string,
    limit: number,
    windowSeconds: number,
  ): Promise<RateLimitResult>;
}

export interface AuditRecord {
  action: "register" | "authenticate" | "session_revoke" | string;
  userId?: string;
  method?: string;
  success: boolean;
  errorCode?: string;
  requestId?: string;
  timestamp: Date;
  meta?: Record<string, unknown>;
}

export interface AuditAdapter {
  write(record: AuditRecord): Promise<void>;
}

export interface IdentitySnapshot {
  userId: string;
  email: string;
  methods: SignInMethodHint[];
}

export interface IdentityAdapter {
  findByEmail(email: string): Promise<MaybeFound<IdentitySnapshot>>;
}

export interface PendingProfileRecord<
  U extends UserBase,
> extends ProfileCompletionState<U> {
  expiresAt: Date;
  consumedAt: Date | null;
}

export interface PendingProfileAdapter<U extends UserBase> {
  create(record: PendingProfileRecord<U>): Promise<void>;
  findById(pendingProfileId: string): Promise<MaybeFound<PendingProfileRecord<U>>>;
  // Atomic compare-and-set: returns false if already consumed/expired/missing.
  consume(pendingProfileId: string): Promise<boolean>;
}

export interface IdempotencyAdapter {
  // Returns false if key already exists and is still active.
  checkAndSet(key: string, ttlSeconds: number): Promise<boolean>;
}

export interface OrganizationAdapter<O extends OrganizationBase> {
  create(input: Omit<O, "id" | "createdAt" | "updatedAt">): Promise<O>;
  findById(organizationId: string): Promise<MaybeFound<O>>;
  findBySlug(slug: string): Promise<MaybeFound<O>>;
  update(organizationId: string, patch: Partial<O>): Promise<MaybeFound<O>>;
}

export interface MembershipAdapter<
  Role extends string,
  M extends MembershipBase<Role>,
> {
  create(input: Omit<M, "id" | "createdAt" | "updatedAt">): Promise<M>;
  findById(membershipId: string): Promise<MaybeFound<M>>;
  findByUserAndOrganization(
    userId: string,
    organizationId: string,
  ): Promise<MaybeFound<M>>;
  listByUser(userId: string): Promise<M[]>;
  listByOrganization(organizationId: string): Promise<M[]>;
  setRole(membershipId: string, role: Role): Promise<MaybeFound<M>>;
  setStatus(
    membershipId: string,
    status: M["status"],
  ): Promise<MaybeFound<M>>;
  delete(membershipId: string): Promise<void>;
}

export interface OrganizationInvite<Role extends string = string> {
  id: string;
  organizationId: string;
  email: string;
  role: Role;
  tokenHash: string;
  invitedByUserId: string;
  expiresAt: Date;
  acceptedAt: Date | null;
  revokedAt: Date | null;
}

export interface OrganizationInviteAdapter<Role extends string = string> {
  create(invite: OrganizationInvite<Role>): Promise<void>;
  findActiveByTokenHash(
    tokenHash: string,
  ): Promise<MaybeFound<OrganizationInvite<Role>>>;
  // Atomic compare-and-set: returns false if invite already used/expired/revoked/missing.
  consume(inviteId: string): Promise<boolean>;
  revoke(inviteId: string): Promise<void>;
}

export interface OrganizationEntitlementsAdapter<
  Feature extends string,
  LimitKey extends string,
> {
  getFeatureOverrides(
    organizationId: string,
  ): Promise<Partial<Record<Feature, boolean>>>;
  getLimitOverrides(
    organizationId: string,
  ): Promise<Partial<Record<LimitKey, number>>>;
  setFeatureOverride(
    organizationId: string,
    feature: Feature,
    enabled: boolean,
  ): Promise<void>;
  setLimitOverride(
    organizationId: string,
    key: LimitKey,
    value: number,
  ): Promise<void>;
}

export interface OrganizationInviteDeliveryPayload<
  Role extends string = string,
> {
  email: string;
  organizationName: string;
  inviteLink: string;
  expiresAt: Date;
  role: Role;
  requestId?: string;
  locale?: string;
}

export interface OrganizationInviteDeliveryHandler<
  Role extends string = string,
> {
  send(
    payload: OrganizationInviteDeliveryPayload<Role>,
  ): Promise<DeliveryResult>;
}

export type DeliveryChannel = "email" | "sms" | "push" | string;

export interface DeliveryResult {
  accepted: boolean;
  providerMessageId?: string;
  queuedAt?: Date;
}

export interface OtpDeliveryPayload {
  email: string;
  code: string;
  expiresAt: Date;
  requestId?: string;
  userId?: string;
  locale?: string;
}

export interface OtpDeliveryHandler {
  send(payload: OtpDeliveryPayload): Promise<DeliveryResult>;
}

export interface MagicLinkDeliveryPayload {
  email: string;
  link: string;
  expiresAt: Date;
  requestId?: string;
  userId?: string;
  locale?: string;
}

export interface MagicLinkDeliveryHandler {
  send(payload: MagicLinkDeliveryPayload): Promise<DeliveryResult>;
}

export interface OutboxMessage {
  id: string;
  channel: DeliveryChannel;
  to: string;
  payload: Record<string, unknown>;
  attempts: number;
  nextAttemptAt: Date;
}

export interface OutboxAdapter {
  enqueue(message: OutboxMessage): Promise<void>;
  markDelivered(messageId: string, providerMessageId?: string): Promise<void>;
  markFailed(messageId: string, reason: string, retryAt?: Date): Promise<void>;
}

export interface CoreAdapters<U extends UserBase> {
  users: UserAdapter<U>;
  sessions: SessionAdapter;
  identity?: IdentityAdapter;
  pendingProfiles?: PendingProfileAdapter<U>;
  idempotency?: IdempotencyAdapter;
  rateLimiter?: RateLimiterAdapter;
  audit?: AuditAdapter;
  outbox?: OutboxAdapter;
  withTransaction?<T>(run: () => Promise<T>): Promise<T>;
}

// Official plugin adapter contracts (custom plugins can define their own)
export interface PasswordCredentialAdapter {
  getPasswordHash(userId: string): Promise<MaybeFound<string>>;
  setPasswordHash(userId: string, passwordHash: string): Promise<void>;
}

export interface OtpChallenge {
  id: string;
  userId: string;
  email: string;
  codeHash: string;
  expiresAt: Date;
  consumedAt: Date | null;
  attempts: number;
}

export interface EmailOtpAdapter {
  createChallenge(input: {
    userId: string;
    email: string;
    codeHash: string;
    expiresAt: Date;
  }): Promise<OtpChallenge>;
  findChallengeById(challengeId: string): Promise<MaybeFound<OtpChallenge>>;
  // Atomic compare-and-set: returns false if already consumed/expired/missing.
  consumeChallenge(challengeId: string): Promise<boolean>;
  // Must be atomic and return the updated attempt count.
  incrementAttempts(challengeId: string): Promise<{ attempts: number }>;
}

export interface EmailOtpPluginHandlers {
  otp: EmailOtpAdapter;
  delivery: OtpDeliveryHandler;
}

export interface MagicLinkToken {
  id: string;
  userId?: string;
  email: string;
  tokenHash: string;
  expiresAt: Date;
  consumedAt: Date | null;
}

export interface MagicLinkAdapter {
  createToken(input: {
    userId?: string;
    email: string;
    tokenHash: string;
    expiresAt: Date;
  }): Promise<MagicLinkToken>;
  findActiveTokenByHash(tokenHash: string): Promise<MaybeFound<MagicLinkToken>>;
  // Atomic compare-and-set: returns false if token already consumed/expired/missing.
  consumeToken(tokenId: string): Promise<boolean>;
}

export interface MagicLinkPluginHandlers {
  links: MagicLinkAdapter;
  delivery: MagicLinkDeliveryHandler;
}

export interface OrganizationsPluginHandlers<
  O extends OrganizationBase,
  Role extends string,
  M extends MembershipBase<Role>,
  Permission extends string,
  Feature extends string,
  LimitKey extends string,
> {
  organizations: OrganizationAdapter<O>;
  organizationSessions: OrganizationSessionAdapter;
  memberships: MembershipAdapter<Role, M>;
  invites: OrganizationInviteAdapter<Role>;
  inviteDelivery: OrganizationInviteDeliveryHandler<Role>;
  entitlements: OrganizationEntitlementsAdapter<Feature, LimitKey>;
  roles: OrganizationRoleCatalog<Role, Permission, Feature, LimitKey>;
  defaultRole: Role;
}

export interface OAuth2AccountAdapter<P extends string> {
  findUserId(provider: P, providerUserId: string): Promise<MaybeFound<string>>;
  linkAccount(input: {
    userId: string;
    provider: P;
    providerUserId: string;
    accessToken?: string;
    refreshToken?: string;
  }): Promise<void>;
}

export interface PasskeyCredential {
  id: string;
  userId: string;
  credentialId: string;
  publicKey: string;
  counter: number;
  transports?: string[];
  createdAt: Date;
  lastUsedAt?: Date;
}

export interface PasskeyAdapter {
  findByCredentialId(
    credentialId: string,
  ): Promise<MaybeFound<PasskeyCredential>>;
  listByUserId(userId: string): Promise<PasskeyCredential[]>;
  create(credential: PasskeyCredential): Promise<void>;
  updateCounter(credentialId: string, counter: number): Promise<void>;
  delete(credentialId: string): Promise<void>;
}

export interface PendingTwoFactorChallenge {
  id: string;
  userId: string;
  primaryMethod: string;
  availableSecondFactors: SecondFactorMethod[];
  expiresAt: Date;
  consumedAt: Date | null;
}

export interface TwoFactorChallengeAdapter {
  create(challenge: PendingTwoFactorChallenge): Promise<void>;
  findById(id: string): Promise<MaybeFound<PendingTwoFactorChallenge>>;
  // Atomic compare-and-set: returns false if challenge already consumed/expired/missing.
  consume(id: string): Promise<boolean>;
}

export interface TotpSecret {
  id: string;
  userId: string;
  encryptedSecret: string;
  createdAt: Date;
  disabledAt?: Date | null;
}

export interface TotpAdapter {
  findActiveByUserId(userId: string): Promise<MaybeFound<TotpSecret>>;
  upsertActive(userId: string, encryptedSecret: string): Promise<void>;
  disable(userId: string): Promise<void>;
}

export interface RecoveryCode {
  id: string;
  userId: string;
  codeHash: string;
  usedAt: Date | null;
}

export interface RecoveryCodeAdapter {
  listActive(userId: string): Promise<RecoveryCode[]>;
  consume(userId: string, codeHash: string): Promise<boolean>;
  replaceAll(userId: string, codeHashes: string[]): Promise<void>;
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

export interface SessionAdapter {
  create(session: Session): Promise<void>;
  findById(id: string): Promise<MaybeFound<Session>>;
  revoke(id: string): Promise<void>;
  revokeAllForUser(userId: string): Promise<void>;
}

export interface OrganizationSessionAdapter {
  setActiveOrganization(
    sessionId: string,
    organizationId?: string,
  ): Promise<MaybeFound<Session>>;
}
```

Why this shape:

- Keeps storage fully custom.
- Avoids weak generic `get/set/delete` flows for security-critical data.
- Allows plugins to own their own persistence contracts without bloating core.
- Enables optional anti-abuse and audit capabilities without forcing a specific infra.
- Supports product-level routing flows (login/register redirects) without coupling UI into core.
- Supports explicit tenant context switching through the organizations plugin API and `organizationSessions.setActiveOrganization(...)`.

### Communication in out-of-band plugins

Use a handler-first model, not event-only delivery:

- Required delivery action (send code/link/invite) should happen through explicit plugin handlers (`OtpDeliveryHandler`, `MagicLinkDeliveryHandler`, `OrganizationInviteDeliveryHandler`).
- Events should wrap the process for observability and policy, not replace the delivery path.
- Optional `outbox` can make delivery resilient (retry, backoff, dead-letter handling).

Why:

- Auth correctness depends on delivery success/failure being explicit.
- Returning a typed error on delivery failure is easier than inferring failures from side-effect events.

## 7. Event model

Use `@oglofus/event-manager` for extensibility.

Rules:

- Core auth must work without any event listeners.
- Pre-events can cancel operations.
- Post-events are non-blocking side effects by default (configurable to `await`).
- Events should include `requestId` when available for traceability.
- Communication plugins use handlers for the actual send; events are emitted around handler execution.

Example events:

```ts
import { Event, CancellableEvent } from "@oglofus/event-manager";

export class PreAuthenticate extends CancellableEvent {
  constructor(
    public readonly input: { method: string; email?: string },
    public readonly requestId?: string,
  ) {
    super();
  }
}

export class PostAuthenticateSuccess extends Event {
  constructor(
    public readonly userId: string,
    public readonly method: string,
    public readonly sessionId: string,
    public readonly requestId?: string,
  ) {
    super();
  }
}

export class PostAuthenticateFailure extends Event {
  constructor(
    public readonly method: string,
    public readonly errorCode: string,
    public readonly requestId?: string,
  ) {
    super();
  }
}

export class PreVerifySecondFactor extends CancellableEvent {
  constructor(
    public readonly method: SecondFactorMethod,
    public readonly pendingAuthId: string,
    public readonly requestId?: string,
  ) {
    super();
  }
}

export class PostVerifySecondFactorSuccess extends Event {
  constructor(
    public readonly userId: string,
    public readonly method: SecondFactorMethod,
    public readonly requestId?: string,
  ) {
    super();
  }
}

export class PreDispatchCommunication extends CancellableEvent {
  constructor(
    public readonly purpose: "email_otp" | "magic_link" | "organization_invite",
    public readonly channel: DeliveryChannel,
    public readonly to: string,
    public readonly requestId?: string,
  ) {
    super();
  }
}

export class PostDispatchCommunicationSuccess extends Event {
  constructor(
    public readonly purpose: "email_otp" | "magic_link" | "organization_invite",
    public readonly channel: DeliveryChannel,
    public readonly to: string,
    public readonly providerMessageId?: string,
    public readonly requestId?: string,
  ) {
    super();
  }
}

export class PostDispatchCommunicationFailure extends Event {
  constructor(
    public readonly purpose: "email_otp" | "magic_link" | "organization_invite",
    public readonly channel: DeliveryChannel,
    public readonly to: string,
    public readonly errorCode: string,
    public readonly requestId?: string,
  ) {
    super();
  }
}
```

## 8. Path-based issue and error contract

```ts
import { CancellableEvent } from "@oglofus/event-manager";

export type PathSegment =
  | { readonly key: PropertyKey }
  | { readonly index: number };

export interface Issue {
  readonly message: string;
  readonly path?: ReadonlyArray<PropertyKey | PathSegment>;
}

export type IssueFactory<TSchema extends object> = {
  [K in Extract<keyof TSchema, string>]-?: (message: string) => Issue;
} & {
  $path: (
    path: ReadonlyArray<PropertyKey | PathSegment>,
    message: string,
  ) => Issue;
  $root: (message: string) => Issue;
};

export function createIssue(
  message: string,
  path?: ReadonlyArray<PropertyKey | PathSegment>,
): Issue {
  if (!path || path.length === 0) return { message };
  return { message, path: [...path] };
}

export function createIssueFactory<TSchema extends object>(
  fields: readonly Extract<keyof TSchema, string>[],
): IssueFactory<TSchema> {
  const factory: Record<string, any> = {
    $path: (path: ReadonlyArray<PropertyKey | PathSegment>, message: string) =>
      createIssue(message, path),
    $root: (message: string) => createIssue(message),
  };

  for (const field of fields) {
    factory[field] = (message: string) => createIssue(message, [field]);
  }

  return factory as IssueFactory<TSchema>;
}

export abstract class AuthIssueEvent<
  TSchema extends object,
> extends CancellableEvent {
  private readonly _issues: Issue[] = [];
  private readonly _issue: IssueFactory<TSchema>;

  constructor(fields: readonly Extract<keyof TSchema, string>[]) {
    super();
    this._issue = createIssueFactory<TSchema>(fields);
    this.cancel = this.cancel.bind(this);
  }

  get issues(): ReadonlyArray<Issue> {
    return this._issues;
  }

  get issue(): IssueFactory<TSchema> {
    return this._issue;
  }

  addIssues(...issues: Array<Issue | undefined>): void {
    for (const issue of issues) {
      if (issue) this._issues.push(issue);
    }
  }

  public cancel(reason?: string): void;
  public cancel(...issues: Issue[]): void;
  public cancel(reason: string, ...issues: Issue[]): void;
  public override cancel(
    reasonOrIssue?: string | Issue,
    ...issues: Issue[]
  ): void {
    let reason = "";

    if (typeof reasonOrIssue === "string") {
      reason = reasonOrIssue;
      this.addIssues(...issues);
    } else if (reasonOrIssue === undefined) {
      this.addIssues(...issues);
    } else {
      this.addIssues(reasonOrIssue, ...issues);
      reason = reasonOrIssue.message;
    }

    super.cancel(reason);
  }
}

export type AuthErrorCode =
  | "INVALID_INPUT"
  | "METHOD_DISABLED"
  | "METHOD_NOT_REGISTERABLE"
  | "ACCOUNT_NOT_FOUND"
  | "ACCOUNT_EXISTS"
  | "ACCOUNT_EXISTS_WITH_DIFFERENT_METHOD"
  | "ORGANIZATION_NOT_FOUND"
  | "MEMBERSHIP_NOT_FOUND"
  | "MEMBERSHIP_FORBIDDEN"
  | "ROLE_INVALID"
  | "ROLE_NOT_ASSIGNABLE"
  | "ORGANIZATION_INVITE_INVALID"
  | "ORGANIZATION_INVITE_EXPIRED"
  | "SEAT_LIMIT_REACHED"
  | "FEATURE_DISABLED"
  | "LIMIT_EXCEEDED"
  | "LAST_OWNER_GUARD"
  | "SESSION_NOT_FOUND"
  | "INVALID_CREDENTIALS"
  | "USER_NOT_FOUND"
  | "CONFLICT"
  | "RATE_LIMITED"
  | "DELIVERY_FAILED"
  | "EMAIL_NOT_VERIFIED"
  | "OTP_EXPIRED"
  | "OTP_INVALID"
  | "MAGIC_LINK_EXPIRED"
  | "MAGIC_LINK_INVALID"
  | "OAUTH2_PROVIDER_DISABLED"
  | "OAUTH2_EXCHANGE_FAILED"
  | "PASSKEY_INVALID_ASSERTION"
  | "PASSKEY_INVALID_ATTESTATION"
  | "PASSKEY_CHALLENGE_EXPIRED"
  | "PROFILE_COMPLETION_REQUIRED"
  | "PROFILE_COMPLETION_EXPIRED"
  | "TWO_FACTOR_REQUIRED"
  | "TWO_FACTOR_INVALID"
  | "TWO_FACTOR_EXPIRED"
  | "RECOVERY_CODE_INVALID"
  | "PLUGIN_METHOD_CONFLICT"
  | "PLUGIN_MISCONFIGURED"
  | "INTERNAL_ERROR";

export class AuthError extends Error {
  constructor(
    public readonly code: AuthErrorCode,
    message: string,
    public readonly status: number,
    public readonly issues: Issue[] = [],
    public readonly meta?: Record<string, unknown>,
  ) {
    super(message);
  }
}

export type TwoFactorRequiredError = AuthError & {
  code: "TWO_FACTOR_REQUIRED";
  meta: TwoFactorRequiredMeta;
};

export type ProfileCompletionRequiredError<U extends UserBase> = AuthError & {
  code: "PROFILE_COMPLETION_REQUIRED";
  meta: ProfileCompletionState<U>;
};

export type OperationResult<TData> =
  | { ok: true; data: TData; issues: Issue[] }
  | { ok: false; error: AuthError; issues: Issue[] };

export type AuthResult<U extends UserBase> =
  | { ok: true; user: U; sessionId: string; issues: Issue[] }
  | {
      ok: false;
      error:
        | AuthError
        | TwoFactorRequiredError
        | ProfileCompletionRequiredError<U>;
      issues: Issue[];
    };

export const successResult = <U extends UserBase>(
  user: U,
  sessionId: string,
  issues: Issue[] = [],
): AuthResult<U> => ({ ok: true, user, sessionId, issues });

export const errorResult = <U extends UserBase>(
  error: AuthError | TwoFactorRequiredError | ProfileCompletionRequiredError<U>,
  issues: Issue[] = [],
): AuthResult<U> => ({ ok: false, error, issues });

export const successOperation = <TData>(
  data: TData,
  issues: Issue[] = [],
): OperationResult<TData> => ({ ok: true, data, issues });

export const errorOperation = <TData = never>(
  error: AuthError,
  issues: Issue[] = [],
): OperationResult<TData> => ({ ok: false, error, issues });
```

## 9. Public API sketch

```ts
export class OglofusAuth<
  U extends UserBase,
  P extends readonly AnyPlugin<U>[],
> {
  constructor(private readonly config: AuthConfig<U, P>) {}

  discover(
    input: DiscoverAccountInput,
    request?: AuthRequestContext,
  ): Promise<OperationResult<DiscoverAccountDecision>> {
    // resolves login/register routing decisions using configured discovery mode
    throw new Error("not implemented");
  }

  authenticate(
    input: AuthenticateInputFromPlugins<P>,
    request?: AuthRequestContext,
  ): Promise<AuthResult<U>> {
    // dispatch by input.method to matching plugin.authenticate
    throw new Error("not implemented");
  }

  register(
    input: RegisterInputFromPlugins<P>,
    request?: AuthRequestContext,
  ): Promise<AuthResult<U>> {
    // dispatch by input.method to matching plugin.register
    throw new Error("not implemented");
  }

  method<M extends PluginMethodsWithApi<P>>(method: M): PluginApiMap<P>[M] {
    // typed access to plugin-exposed API
    // examples: request OTP, request magic link, begin passkey registration, begin TOTP enrollment
    throw new Error("not implemented");
  }

  verifySecondFactor(
    input: TwoFactorVerifyInput,
    request?: AuthRequestContext,
  ): Promise<AuthResult<U>> {
    // delegated to `two_factor` plugin API
    throw new Error("not implemented");
  }

  completeProfile(
    input: CompleteProfileInput<U>,
    request?: AuthRequestContext,
  ): Promise<AuthResult<U>> {
    // consumes pending profile state and completes registration/auth flow
    throw new Error("not implemented");
  }

  validateSession(
    sessionId: string,
    request?: AuthRequestContext,
  ): Promise<{ ok: true; userId: string } | { ok: false }> {
    throw new Error("not implemented");
  }

  signOut(sessionId: string, request?: AuthRequestContext): Promise<void> {
    throw new Error("not implemented");
  }
}
```

## 10. Third-party libraries

- `arctic`: OAuth2 provider integrations and token/code exchange.
- `oslo`: cryptography helpers (password hashing utilities, secure random values, cookies/tokens as needed).
- `@simplewebauthn/server` (or equivalent): passkey/WebAuthn verification primitives.
- `otpauth` (or equivalent): TOTP enrollment and verification primitives.

Keep wrappers thin so developer can swap providers later with minimal breakage.

## 11. Security baseline for v1

- Password hashing with modern algorithm (Argon2id preferred).
- Constant-time compare for secrets.
- OTP attempts limit + expiry enforcement.
- Magic links are single-use, short-lived, and stored as hashes (never plaintext tokens).
- OTP/magic-link send failures return explicit `DELIVERY_FAILED` (never silent event-only failures).
- OTP/magic-link/2FA challenge consumption must be atomic to prevent replay races.
- OTP verification must be bound to `challengeId` (never resolve active challenge only by email).
- Passkey verification must validate challenge, origin, RP ID, and signature counter.
- OAuth2 callbacks must use `state`/PKCE and be idempotent against duplicate provider callbacks.
- Session expiration + rotation support.
- `accountDiscovery.mode = "private"` should avoid leaking user existence through explicit routing messages.
- `accountDiscovery.mode = "explicit"` should be used only where product requirements justify enumeration risk.
- Emit security events for suspicious behavior (rate limit hit, repeated failures).
- Never log OTP codes, raw magic-link tokens, or unredacted passkey payloads.
- Rate limit sensitive flows (`register`, `authenticate`, OTP verify) by IP and identity key.
- In `accountDiscovery.mode = "explicit"`, also rate limit discovery endpoints to reduce enumeration abuse.
- Enforce uniqueness on normalized email value in storage.
- Organization-scoped operations must verify active membership and tenant boundary on every check.
- Suspended/invited memberships must fail permission/feature/limit checks until active.
- Enforce "last owner" guard (cannot remove/demote the final owner).
- Organization invite tokens must be one-way hashed and single-use with expiry.
- Invite acceptance should require normalized invite email to match authenticated user email (unless explicitly configured otherwise).
- Seat-limit checks and membership creation must be atomic.
- Role/feature/limit checks must run server-side on every protected action (never trust client claims).
- `organizations.setActiveOrganization` must verify membership is active and tenant is still accessible at the time of switch.
- Two-factor challenges are short-lived and bound to a `pendingAuthId`.
- `pendingAuthId` must be bound to the primary auth attempt and invalidated on timeout/use.
- Pending profile-completion states must be short-lived and one-time consumable.
- `completeProfile` must reject incomplete submissions with field/path issues from `missingFields`.
- Profile completion `prefill` payloads must include only allowlisted non-sensitive user fields.
- If OAuth provider email is unverified/missing, require additional verification or profile completion.
- TOTP seeds are encrypted at rest and never returned after enrollment.
- Recovery codes are one-way hashed and shown only at generation time.
- Use idempotency keys for externally retried registration flows where possible.

## 12. Example consumer usage

```ts
import {
  OglofusAuth,
  passwordPlugin,
  emailOtpPlugin,
  magicLinkPlugin,
  oauth2Plugin,
  passkeyPlugin,
  twoFactorPlugin,
  organizationsPlugin,
  type UserBase,
  type OrganizationBase,
  type MembershipBase,
  type PasswordCredentialAdapter,
  type EmailOtpAdapter,
  type OtpDeliveryHandler,
  type MagicLinkAdapter,
  type MagicLinkDeliveryHandler,
  type IdentityAdapter,
  type PendingProfileAdapter,
  type IdempotencyAdapter,
  type OrganizationAdapter,
  type MembershipAdapter,
  type OrganizationInviteAdapter,
  type OrganizationInviteDeliveryHandler,
  type OrganizationEntitlementsAdapter,
  type OAuth2AccountAdapter,
  type PasskeyAdapter,
  type TwoFactorChallengeAdapter,
  type TotpAdapter,
  type RecoveryCodeAdapter,
} from "@oglofus/auth";

interface User extends UserBase {
  given_name: string;
  family_name: string;
}

type OrgRole = "owner" | "admin" | "member" | "billing";
type OrgPermission =
  | "org.manage"
  | "members.manage"
  | "billing.manage"
  | "project.read"
  | "project.write";
type OrgFeature = "api_access" | "audit_export" | "sso";
type OrgLimitKey = "seats" | "projects" | "api_keys";

interface Organization extends OrganizationBase {
  billing_email: string;
  industry?: "saas" | "agency" | "ecommerce";
}

interface Membership extends MembershipBase<OrgRole> {
  invitedByUserId?: string;
}

const auth = new OglofusAuth({
  accountDiscovery: {
    mode: "explicit",
  },
  normalize: {
    email: (value) => value.trim().toLowerCase(),
  },
  validateConfigOnStart: true,
  adapters: {
    identity: {
      findByEmail: async (email) => null,
    } satisfies IdentityAdapter,
    pendingProfiles: {
      create: async (record) => {},
      findById: async (pendingProfileId) => null,
      consume: async (pendingProfileId) => true,
    } satisfies PendingProfileAdapter<User>,
    idempotency: {
      checkAndSet: async (key, ttlSeconds) => true,
    } satisfies IdempotencyAdapter,
    users: {
      findById: async (id) => null,
      findByEmail: async (email) => null,
      create: async (input) => ({
        id: crypto.randomUUID(),
        email: input.email,
        emailVerified: false,
        createdAt: new Date(),
        updatedAt: new Date(),
        given_name: "",
        family_name: "",
      }),
      update: async (id, patch) => {
        throw new Error("implement update");
      },
    },
    sessions: {
      create: async (session) => {},
      findById: async (id) => null,
      revoke: async (id) => {},
      revokeAllForUser: async (userId) => {},
    },
  },
  plugins: [
    passwordPlugin<User, "given_name" | "family_name">({
      requiredProfileFields: ["given_name", "family_name"] as const,
      credentials: {
        getPasswordHash: async (userId) => null,
        setPasswordHash: async (userId, hash) => {},
      } satisfies PasswordCredentialAdapter,
    }),
    emailOtpPlugin<User, "given_name" | "family_name">({
      requiredProfileFields: ["given_name", "family_name"] as const,
      otp: {
        createChallenge: async (input) => ({
          id: crypto.randomUUID(),
          userId: input.userId,
          email: input.email,
          codeHash: input.codeHash,
          expiresAt: input.expiresAt,
          consumedAt: null,
          attempts: 0,
        }),
        findChallengeById: async (challengeId) => null,
        consumeChallenge: async (id) => true,
        incrementAttempts: async (id) => ({ attempts: 1 }),
      } satisfies EmailOtpAdapter,
      delivery: {
        send: async (payload) => ({
          accepted: true,
          providerMessageId: "msg_otp_123",
          queuedAt: new Date(),
        }),
      } satisfies OtpDeliveryHandler,
    }),
    magicLinkPlugin<User, "given_name" | "family_name">({
      requiredProfileFields: ["given_name", "family_name"] as const,
      links: {
        createToken: async (input) => ({
          id: crypto.randomUUID(),
          userId: input.userId,
          email: input.email,
          tokenHash: input.tokenHash,
          expiresAt: input.expiresAt,
          consumedAt: null,
        }),
        findActiveTokenByHash: async (tokenHash) => null,
        consumeToken: async (tokenId) => true,
      } satisfies MagicLinkAdapter,
      delivery: {
        send: async (payload) => ({
          accepted: true,
          providerMessageId: "msg_link_456",
          queuedAt: new Date(),
        }),
      } satisfies MagicLinkDeliveryHandler,
    }),
    oauth2Plugin<User, "google" | "apple">({
      providers: ["google", "apple"] as const,
      accounts: {
        findUserId: async (provider, providerUserId) => null,
        linkAccount: async (input) => {},
      } satisfies OAuth2AccountAdapter<"google" | "apple">,
    }),
    passkeyPlugin<User, "given_name" | "family_name">({
      requiredProfileFields: ["given_name", "family_name"] as const,
      passkeys: {
        findByCredentialId: async (credentialId) => null,
        listByUserId: async (userId) => [],
        create: async (credential) => {},
        updateCounter: async (credentialId, counter) => {},
        delete: async (credentialId) => {},
      } satisfies PasskeyAdapter,
    }),
    twoFactorPlugin<User>({
      requiredMethods: ["totp"] as const,
      challenges: {
        create: async (challenge) => {},
        findById: async (id) => null,
        consume: async (id) => true,
      } satisfies TwoFactorChallengeAdapter,
      totp: {
        findActiveByUserId: async (userId) => null,
        upsertActive: async (userId, encryptedSecret) => {},
        disable: async (userId) => {},
      } satisfies TotpAdapter,
      recoveryCodes: {
        listActive: async (userId) => [],
        consume: async (userId, codeHash) => false,
        replaceAll: async (userId, codeHashes) => {},
      } satisfies RecoveryCodeAdapter,
    }),
    organizationsPlugin<
      User,
      Organization,
      OrgRole,
      Membership,
      OrgPermission,
      OrgFeature,
      OrgLimitKey,
      "billing_email"
    >({
      organizationRequiredFields: ["billing_email"] as const,
      handlers: {
        organizations: {
          create: async (input) => ({
            id: crypto.randomUUID(),
            slug: input.slug,
            name: input.name,
            billing_email: input.billing_email ?? "billing@example.com",
            industry: "saas",
            createdAt: new Date(),
            updatedAt: new Date(),
          }),
          findById: async (organizationId) => null,
          findBySlug: async (slug) => null,
          update: async (organizationId, patch) => {
            throw new Error("implement org update");
          },
        } satisfies OrganizationAdapter<Organization>,
        memberships: {
          create: async (input) => ({
            id: crypto.randomUUID(),
            organizationId: input.organizationId,
            userId: input.userId,
            role: input.role,
            status: input.status,
            invitedByUserId: input.invitedByUserId,
            createdAt: new Date(),
            updatedAt: new Date(),
          }),
          findById: async (membershipId) => null,
          findByUserAndOrganization: async (userId, organizationId) => null,
          listByUser: async (userId) => [],
          listByOrganization: async (organizationId) => [],
          setRole: async (membershipId, role) => {
            throw new Error("implement role update");
          },
          setStatus: async (membershipId, status) => {
            throw new Error("implement status update");
          },
          delete: async (membershipId) => {},
        } satisfies MembershipAdapter<OrgRole, Membership>,
        invites: {
          create: async (invite) => {},
          findActiveByTokenHash: async (tokenHash) => null,
          consume: async (inviteId) => true,
          revoke: async (inviteId) => {},
        } satisfies OrganizationInviteAdapter<OrgRole>,
        inviteDelivery: {
          send: async (payload) => ({
            accepted: true,
            providerMessageId: "msg_invite_789",
            queuedAt: new Date(),
          }),
        } satisfies OrganizationInviteDeliveryHandler<OrgRole>,
        entitlements: {
          getFeatureOverrides: async (organizationId) => ({}),
          getLimitOverrides: async (organizationId) => ({ seats: 5 }),
          setFeatureOverride: async (organizationId, feature, enabled) => {},
          setLimitOverride: async (organizationId, key, value) => {},
        } satisfies OrganizationEntitlementsAdapter<OrgFeature, OrgLimitKey>,
        roles: {
          owner: {
            permissions: [
              "org.manage",
              "members.manage",
              "billing.manage",
              "project.read",
              "project.write",
            ],
            features: { api_access: true, audit_export: true, sso: true },
            limits: { seats: 100, projects: 500, api_keys: 200 },
            system: { owner: true },
          },
          admin: {
            permissions: ["members.manage", "project.read", "project.write"],
            features: { api_access: true, audit_export: false, sso: true },
            limits: { projects: 200 },
          },
          member: {
            permissions: ["project.read"],
            features: { api_access: false, audit_export: false, sso: false },
            limits: { projects: 20 },
            system: { default: true },
          },
          billing: {
            permissions: ["billing.manage", "project.read"],
            features: { api_access: false, audit_export: true, sso: true },
            limits: { projects: 50 },
          },
        },
        defaultRole: "member",
      },
    }),
  ] as const,
});

await auth.register(
  {
    method: "password",
    email: "nikos@example.com",
    password: "super-secret",
    given_name: "Nikos",
    family_name: "Gram",
  },
  {
    requestId: "req_01HZYJ3N",
    ip: "203.0.113.8",
  },
);

const otpApi = auth.method("email_otp");
const otpRequested = await otpApi.request({
  email: "nikos@example.com",
  locale: "en-US",
});
if (!otpRequested.ok) {
  console.error(otpRequested.error.code, otpRequested.issues);
}

const orgApi = auth.method("organizations");
const createdOrg = await orgApi.createOrganization({
  name: "Acme Inc",
  slug: "acme-inc",
  profile: { billing_email: "billing@acme.inc", industry: "saas" },
});
if (createdOrg.ok) {
  await orgApi.inviteMember({
    organizationId: createdOrg.data.organization.id,
    email: "teammate@example.com",
    role: "member",
  });
}

const canManageMembers = await orgApi.checkPermission({
  organizationId: "org_123",
  userId: "user_123",
  permission: "members.manage",
});

await orgApi.setFeatureOverride({
  organizationId: "org_123",
  feature: "sso",
  enabled: true,
});

await orgApi.setLimitOverride({
  organizationId: "org_123",
  key: "seats",
  value: 25,
});

const orgApi = auth.method("organizations");
await orgApi.setActiveOrganization({
  sessionId: "session_123",
  organizationId: "org_123",
});

await auth.verifySecondFactor({
  method: "totp",
  pendingAuthId: "pa_01HZYM23",
  code: "123456",
});

// TypeScript error (missing given_name/family_name for local register):
// await auth.register({ method: "password", email: "x", password: "y" });

// TypeScript error (missing required organization field `billing_email`):
// await orgApi.createOrganization({ name: "No Billing", slug: "no-billing", profile: {} });
```

## 13. Scenario suite (normal + extreme)

Assumption for product routing examples below:

- `accountDiscovery.mode` is set to `"explicit"` unless a scenario explicitly switches to `"private"`.

### 13.1 Normal scenarios (expected product flows)

### Product scenario 1: login email not found -> redirect to register

```ts
const d1 = await auth.discover({
  intent: "login",
  email: "new-user@example.com",
});

if (d1.ok && d1.data.action === "redirect_register") {
  // UI route: /register?email=new-user@example.com
  // Show copy for d1.data.messageKey ("auth.no_account")
}
```

### Product scenario 2: register email exists via Google -> redirect to login with suggestions

```ts
const d2 = await auth.discover({
  intent: "register",
  email: "existing@example.com",
});

if (d2.ok && d2.data.action === "redirect_login") {
  // UI route: /login?email=existing@example.com
  // Example suggested methods: [{ method: "oauth2", provider: "google" }, { method: "email_otp" }]
}
```

### Product scenario 3: Google sign-in missing required fields -> profile completion

```ts
const authRes = await auth.authenticate({
  method: "oauth2",
  provider: "google",
  authorizationCode: "code",
  redirectUri: "https://app.example.com/callback",
});

if (!authRes.ok && authRes.error.code === "PROFILE_COMPLETION_REQUIRED") {
  const { pendingProfileId, missingFields, prefill } = authRes.error.meta;
  // UI route: /register/complete?pendingProfileId=...
  // Render only missing fields, prefilled with available provider data.
}

const done = await auth.completeProfile({
  pendingProfileId: "pp_123",
  profile: { given_name: "Nikos", family_name: "Gram" },
});
```

### Product scenario 4: password login with required 2FA

```ts
const step1 = await auth.authenticate({
  method: "password",
  email: "nikos@example.com",
  password: "secret",
});

if (!step1.ok && step1.error.code === "TWO_FACTOR_REQUIRED") {
  const step2 = await auth.verifySecondFactor({
    method: "totp",
    pendingAuthId: step1.error.meta.pendingAuthId,
    code: "123456",
  });
}
```

### Product scenario 5: email OTP request + verify via challenge ID

```ts
const otpApi = auth.method("email_otp");
const requested = await otpApi.request({ email: "nikos@example.com" });

if (requested.ok) {
  const login = await auth.authenticate({
    method: "email_otp",
    challengeId: requested.data.challengeId,
    code: "123456",
  });
}
```

### Product scenario 6: create organization + invite member

```ts
const orgApi = auth.method("organizations");
const org = await orgApi.createOrganization({
  name: "Acme Inc",
  slug: "acme-inc",
  profile: { billing_email: "billing@acme.inc" },
});

if (org.ok) {
  await orgApi.inviteMember({
    organizationId: org.data.organization.id,
    email: "teammate@example.com",
    role: "member",
  });
}
```

### Product scenario 7: private discovery mode (anti-enumeration UX)

```ts
const privateAuth = new OglofusAuth({
  accountDiscovery: { mode: "private" },
  adapters,
  plugins,
});

const decision = await privateAuth.discover({
  intent: "login",
  email: "unknown@example.com",
});
// Expected: `continue_generic`
```

### Product scenario 8: switch active organization after membership checks

```ts
const orgApi = auth.method("organizations");
const switched = await orgApi.setActiveOrganization({
  sessionId: "session_123",
  organizationId: "org_123",
});
if (!switched.ok) {
  // expected on forbidden tenant access: MEMBERSHIP_FORBIDDEN
}
```

### 13.2 Extreme scenarios (abuse, races, misconfiguration)

### A) Register capability inference bug

Issue found:

- Plugins with optional `register` could accidentally disappear from `RegisterInputFromPlugins` union.

Fix in spec:

- Added explicit `supports.register` and switched type inference to this flag.

```ts
const saml = samlPlugin<User>({
  supports: { register: false },
});

// TypeScript should reject this, since SAML plugin does not support register:
// await auth.register({ method: "saml", email: "a@b.com" });
```

### B) OTP request delivery ambiguity

Issue found:

- Event-only delivery makes it hard to tell if the OTP was actually dispatched.

Fix in spec:

- Added handler-first delivery contracts and `EmailOtpPluginApi.request(...)` with explicit disposition.
- Added optional `outbox` adapter for reliable retries.

```ts
const otpApi = auth.method("email_otp");
const res = await otpApi.request({ email: "nikos@example.com" });

if (res.ok) {
  // "sent" or "queued" are both explicit states
  console.log(res.data.disposition, res.data.challengeId);
}
```

### C) One-time token replay race

Issue found:

- Concurrent requests could consume same OTP/magic link twice.

Fix in spec:

- `consumeChallenge`, `consumeToken`, and 2FA `consume` now require atomic compare-and-set and return `boolean`.
- OTP verify path is bound to `challengeId` to prevent selecting wrong active challenge.

```ts
const consumed = await adapters.magicLink.consumeToken(tokenId);
if (!consumed) {
  return errorOperation(
    new AuthError("MAGIC_LINK_INVALID", "Link already used or expired.", 400, [
      createIssue("Link is no longer valid", ["token"]),
    ]),
  );
}
```

### D) 2FA bypass risk

Issue found:

- Session issuance before second-factor completion would bypass policy.

Fix in spec:

- Core principle now enforces session issuance only after all required factors pass.
- Primary methods return `TWO_FACTOR_REQUIRED` with `pendingAuthId` and no session.

```ts
const step1 = await auth.authenticate({
  method: "password",
  email: "nikos@example.com",
  password: "secret",
});

if (!step1.ok && step1.error.code === "TWO_FACTOR_REQUIRED") {
  const step2 = await auth.verifySecondFactor({
    method: "totp",
    pendingAuthId: step1.error.meta.pendingAuthId,
    code: "123456",
  });
  // session is created only here on success
}
```

### E) Nested passkey validation feedback

Issue found:

- Flat errors are insufficient for WebAuthn payload debugging.

Fix in spec:

- Path-based issues support deep payload pointers for client UIs.

```ts
event.cancel(
  event.issue.$path(
    ["assertion", "response", "authenticatorData"],
    "Missing authenticatorData",
  ),
);
```

### F) Non-session operation consistency

Issue found:

- Non-authenticate operations (`request`, enrollment flows) need typed success/error with issues too.

Fix in spec:

- Added `OperationResult<TData>` + helpers `successOperation`/`errorOperation`.

```ts
return successOperation({ disposition: "queued", challengeId });
```

### G) Account enumeration risk vs UX requirement

Issue found:

- Product teams may need explicit redirect copy, but that can leak account existence.

Fix in spec:

- Added `accountDiscovery.mode`:
  - `private`: generic routing/copy (`continue_generic`)
  - `explicit`: product-friendly redirects with account-aware copy

```ts
const privateAuth = new OglofusAuth({
  accountDiscovery: { mode: "private" },
  adapters,
  plugins,
});
```

### H) Duplicate OAuth callback replay

Issue found:

- OAuth providers and proxies can replay callbacks; without idempotency, accounts can be linked twice.

Fix in spec:

- Added `IdempotencyAdapter.checkAndSet(...)` and OAuth callback idempotency requirement.

```ts
const first = await adapters.idempotency?.checkAndSet(
  `oauth:${provider}:${state}`,
  300,
);
if (!first) {
  return errorOperation(new AuthError("CONFLICT", "Duplicate callback.", 409));
}
```

### I) Slow/out-of-order delivery

Issue found:

- OTP or magic links may arrive late, after expiry or after a new challenge replaced old one.

Fix in spec:

- Delivery API reports explicit status.
- Challenge consumption is atomic and expiry-aware.
- Optional outbox supports retry/backoff and observability.

### J) Orphaned profile completion state

Issue found:

- Users may abandon profile completion after OAuth start, leaving stale pending state.

Fix in spec:

- Added `pendingProfiles` adapter with short TTL + one-time consume.
- Added `PROFILE_COMPLETION_EXPIRED` code.

### K) Passkey counter regression (cloned authenticator risk)

Issue found:

- Assertion counter not increasing can indicate cloned credential/replay.

Fix in spec:

- `PasskeyAdapter.updateCounter(...)` is required and security baseline mandates strict counter checks.

### L) Email canonicalization mismatch

Issue found:

- `Nikos@Example.com` and `nikos@example.com` can accidentally become separate accounts without normalized uniqueness.

Fix in spec:

- Added configurable email normalization.
- Discovery and identity lookups operate on normalized email.
- Storage should enforce uniqueness on normalized email representation.

### M) Challenge flooding / denial scenario

Issue found:

- Repeated OTP/magic-link requests can flood users and degrade deliverability.

Fix in spec:

- Rate limiter is required in production deployments.
- Out-of-band request APIs should apply per-email + per-IP cooldown windows.
- Outbox + audit provide visibility and mitigation hooks.

### N) Cross-organization data leakage

Issue found:

- APIs that trust only `userId` can leak tenant data across organizations.

Fix in spec:

- Authorization checks require both `organizationId` and active membership.
- Security baseline now mandates tenant-bound checks on every org-scoped operation.

### O) Last owner demotion/removal

Issue found:

- Demoting/removing the final owner can orphan an organization.

Fix in spec:

- Added `LAST_OWNER_GUARD` error.
- Role/membership updates must block operations that remove the final owner.

### P) Seat-limit race condition

Issue found:

- Concurrent invites/joins can exceed seat limits when checks are not atomic.

Fix in spec:

- Membership create + limit evaluation must be transactionally atomic.
- Added explicit `SEAT_LIMIT_REACHED` error code.

### Q) Organization invite replay

Issue found:

- Reused invite links can re-add users or bypass invite lifecycle.

Fix in spec:

- Invite tokens are hashed, expiring, and one-time consumable via atomic consume.
- Added `ORGANIZATION_INVITE_INVALID` and `ORGANIZATION_INVITE_EXPIRED`.

### R) Broken role catalog setup

Issue found:

- Cyclic role inheritance or missing default/owner role makes authorization ambiguous.

Fix in spec:

- Startup invariants validate role graph and required system roles before startup.

### S) Privilege escalation via custom role assignment

Issue found:

- Allowing admins to assign owner-capable roles can escalate privileges unintentionally.

Fix in spec:

- Added `ROLE_NOT_ASSIGNABLE` error for disallowed assignments.
- Implement role-assignment policy checks in organization plugin before membership updates.

### T) Entitlement override drift

Issue found:

- Feature/limit overrides can drift from expected plan defaults and create hidden behavior.

Fix in spec:

- Added explicit APIs for feature/limit overrides and entitlement snapshot reads.
- Keep precedence deterministic and auditable:
  role defaults -> organization overrides -> runtime policy checks.

### U) Organization invite email mismatch takeover

Issue found:

- If invite accept checks only token validity, any authenticated user could accept another user's invite link.

Fix in spec:

- Invite accept flow should require normalized invite email to match authenticated user email unless explicitly overridden by policy.
- Return `MEMBERSHIP_FORBIDDEN` (or plugin-specific policy error) on mismatch.

### V) Stale active organization after membership suspension

Issue found:

- A session can keep a stale `activeOrganizationId` after membership is suspended/deleted.

Fix in spec:

- `organizations.setActiveOrganization` and org-scoped permission checks must verify current membership status every time.
- Suspended/invited memberships must not authorize organization actions.

### W) Auth-method and domain-plugin method collision

Issue found:

- Custom plugin method naming collisions can shadow APIs or break method dispatch.

Fix in spec:

- Startup validation now forbids collisions between auth-method plugin names and domain-plugin names.

### X) Partial org bootstrap without transaction

Issue found:

- Organization creation can succeed while owner membership creation fails, leaving orphan organizations.

Fix in spec:

- Org bootstrap (`createOrganization` + initial owner membership) must be atomic through `withTransaction` or adapter-level atomic primitives.

### Y) External retry duplicate registration

Issue found:

- Client/proxy retries can create duplicate register attempts for the same logical action.

Fix in spec:

- Use `IdempotencyAdapter` for externally retried registration/provider callbacks and return deterministic conflicts.

## 14. Plugin author contract (minimum)

- Validate inputs at runtime (do not rely only on TypeScript types).
- Set plugin `kind` correctly (`auth_method` vs `domain`) and keep `method` names globally unique.
- Declare `supports.register` truthfully and keep it aligned with runtime capability.
- Add path-based issues (`event.issue.<field>()`, `event.issue.$path(...)`) for validation failures.
- Return `AuthError` codes instead of throwing raw errors for expected failures.
- Respect configured account discovery mode and do not bypass privacy policy in plugin responses.
- Keep side effects idempotent when possible (especially registration and account linking).
- Emit meaningful audit metadata (`method`, `requestId`, failure reason code).
- Never persist plaintext secrets (`password`, OTP code, tokens without encryption policy).
- For out-of-band methods (email OTP/magic link), enforce one-time use and strict expiration.
- For email OTP verify/register, require and validate `challengeId` (avoid "latest challenge by email" lookup).
- For out-of-band methods, use explicit delivery handlers for sending; use events only for observability/policy.
- Use atomic compare-and-set for one-time credentials/challenges/recovery-code consumption.
- For passkeys, strictly verify RP ID/origin/challenge and store updated counters after successful assertions.
- For 2FA, bind second-factor verification to `pendingAuthId` and consume challenge on success.
- For OAuth/passkey partial signups, return `PROFILE_COMPLETION_REQUIRED` with missing fields and pending profile ID.
- For organizations, enforce tenant scoping and membership status checks before permission/feature/limit evaluation.
- For organizations, ensure bootstrap and seat-limited membership creation are atomic.
- For organizations, validate role catalog on startup (default role, owner role, no cyclic inheritance).
- For organizations, keep entitlement resolution deterministic:
  role defaults -> organization overrides -> runtime policy checks.

## 15. Framework boundary (HTTP/session transport)

`OglofusAuth` stays framework-agnostic. Frameworks are responsible for transporting `sessionId`
between client and server (typically via secure cookies).

Recommended baseline:

- Use an `HttpOnly` session cookie.
- Use `SameSite=Lax` for regular web apps unless cross-site flow requires `None`.
- Use `Secure=true` in production.
- Rotate/revoke cookie on sign-out and invalid sessions.
- Always call `validateSession(...)` server-side, never trust client user IDs.

Suggested helper shape (can live in a separate package like `@oglofus/auth-http`):

```ts
export type SessionCookieConfig = {
  name: string;
  secure: boolean;
  sameSite: "lax" | "strict" | "none";
  path: string;
};
```

This is a transport helper recommendation, not core auth logic.

## 16. Framework setup examples

### 16.1 Next.js (App Router) basic password auth

#### `src/lib/auth.ts`

```ts
import {
  OglofusAuth,
  passwordPlugin,
  type UserBase,
  type PasswordCredentialAdapter,
  type SessionAdapter,
  type UserAdapter,
} from "@oglofus/auth";

interface User extends UserBase {}

const users: UserAdapter<User> = {
  findById: async (id) => null,
  findByEmail: async (email) => null,
  create: async (input) => ({
    id: crypto.randomUUID(),
    email: input.email,
    emailVerified: true,
    createdAt: new Date(),
    updatedAt: new Date(),
  }),
  update: async (id, patch) => {
    throw new Error("implement user update");
  },
};

const sessions: SessionAdapter = {
  create: async (session) => {},
  findById: async (id) => null,
  revoke: async (id) => {},
  revokeAllForUser: async (userId) => {},
};

const credentials: PasswordCredentialAdapter = {
  getPasswordHash: async (userId) => null,
  setPasswordHash: async (userId, passwordHash) => {},
};

export const auth = new OglofusAuth({
  adapters: { users, sessions },
  plugins: [
    passwordPlugin<User, never>({
      requiredProfileFields: [] as const,
      credentials,
    }),
  ] as const,
});
```

#### `src/lib/session-cookie.ts`

```ts
import type { NextResponse } from "next/server";

export const SESSION_COOKIE = "sid";

const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "lax" as const,
  path: "/",
  maxAge: 60 * 60 * 24 * 30,
};

export function setSessionCookie(res: NextResponse, sessionId: string): void {
  res.cookies.set(SESSION_COOKIE, sessionId, cookieOptions);
}

export function clearSessionCookie(res: NextResponse): void {
  res.cookies.set(SESSION_COOKIE, "", { ...cookieOptions, maxAge: 0 });
}
```

#### `src/app/api/auth/register/route.ts`

```ts
import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { setSessionCookie } from "@/lib/session-cookie";

export async function POST(req: NextRequest): Promise<NextResponse> {
  const { email, password } = await req.json();

  const result = await auth.register(
    { method: "password", email, password },
    {
      requestId: crypto.randomUUID(),
      ip: req.headers.get("x-forwarded-for") ?? undefined,
      userAgent: req.headers.get("user-agent") ?? undefined,
    },
  );

  if (!result.ok) {
    return NextResponse.json(
      { code: result.error.code, issues: result.issues },
      { status: result.error.status },
    );
  }

  const res = NextResponse.json({ user: result.user });
  setSessionCookie(res, result.sessionId);
  return res;
}
```

#### `src/app/api/auth/login/route.ts`

```ts
import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { setSessionCookie } from "@/lib/session-cookie";

export async function POST(req: NextRequest): Promise<NextResponse> {
  const { email, password } = await req.json();

  const result = await auth.authenticate(
    { method: "password", email, password },
    {
      requestId: crypto.randomUUID(),
      ip: req.headers.get("x-forwarded-for") ?? undefined,
      userAgent: req.headers.get("user-agent") ?? undefined,
    },
  );

  if (!result.ok) {
    return NextResponse.json(
      { code: result.error.code, issues: result.issues },
      { status: result.error.status },
    );
  }

  const res = NextResponse.json({ user: result.user });
  setSessionCookie(res, result.sessionId);
  return res;
}
```

#### `src/app/api/auth/logout/route.ts`

```ts
import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { SESSION_COOKIE, clearSessionCookie } from "@/lib/session-cookie";

export async function POST(req: NextRequest): Promise<NextResponse> {
  const sessionId = req.cookies.get(SESSION_COOKIE)?.value;
  if (sessionId) {
    await auth.signOut(sessionId, {
      requestId: crypto.randomUUID(),
      ip: req.headers.get("x-forwarded-for") ?? undefined,
      userAgent: req.headers.get("user-agent") ?? undefined,
    });
  }

  const res = NextResponse.json({ ok: true });
  clearSessionCookie(res);
  return res;
}
```

#### `src/app/api/auth/me/route.ts`

```ts
import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { SESSION_COOKIE, clearSessionCookie } from "@/lib/session-cookie";

export async function GET(req: NextRequest): Promise<NextResponse> {
  const sessionId = req.cookies.get(SESSION_COOKIE)?.value;
  if (!sessionId) {
    return NextResponse.json({ ok: false }, { status: 401 });
  }

  const session = await auth.validateSession(sessionId, {
    requestId: crypto.randomUUID(),
    ip: req.headers.get("x-forwarded-for") ?? undefined,
    userAgent: req.headers.get("user-agent") ?? undefined,
  });

  if (!session.ok) {
    const res = NextResponse.json({ ok: false }, { status: 401 });
    clearSessionCookie(res);
    return res;
  }

  return NextResponse.json({ ok: true, userId: session.userId });
}
```

### 16.2 SvelteKit basic OTP auth

Flow:

1. `POST /auth/otp/request` sends code and returns `challengeId`.
2. `POST /auth/otp/verify` verifies `{ challengeId, code }`, returns session cookie.
3. If the product wants OTP-based sign-up, call `auth.register(...)` with the same `challengeId`
   and required local profile fields instead of `authenticate(...)`.

#### `src/lib/server/auth.ts`

```ts
import {
  OglofusAuth,
  emailOtpPlugin,
  type EmailOtpAdapter,
  type OtpDeliveryHandler,
  type SessionAdapter,
  type UserAdapter,
  type UserBase,
} from "@oglofus/auth";

interface User extends UserBase {}

const users: UserAdapter<User> = {
  findById: async (id) => null,
  findByEmail: async (email) => null,
  create: async (input) => ({
    id: crypto.randomUUID(),
    email: input.email,
    emailVerified: true,
    createdAt: new Date(),
    updatedAt: new Date(),
  }),
  update: async (id, patch) => {
    throw new Error("implement user update");
  },
};

const sessions: SessionAdapter = {
  create: async (session) => {},
  findById: async (id) => null,
  revoke: async (id) => {},
  revokeAllForUser: async (userId) => {},
};

const otp: EmailOtpAdapter = {
  createChallenge: async (input) => ({
    id: crypto.randomUUID(),
    userId: input.userId,
    email: input.email,
    codeHash: input.codeHash,
    expiresAt: input.expiresAt,
    consumedAt: null,
    attempts: 0,
  }),
  findChallengeById: async (challengeId) => null,
  consumeChallenge: async (challengeId) => true,
  incrementAttempts: async (challengeId) => ({ attempts: 1 }),
};

const delivery: OtpDeliveryHandler = {
  send: async (payload) => {
    console.log("Send OTP", payload.email);
    return { accepted: true, queuedAt: new Date() };
  },
};

export const auth = new OglofusAuth({
  adapters: { users, sessions },
  plugins: [
    emailOtpPlugin<User, never>({
      requiredProfileFields: [] as const,
      otp,
      delivery,
    }),
  ] as const,
});
```

#### `src/routes/auth/otp/request/+server.ts`

```ts
import { json } from "@sveltejs/kit";
import type { RequestHandler } from "./$types";
import { auth } from "$lib/server/auth";

export const POST: RequestHandler = async ({ request, getClientAddress }) => {
  const { email } = await request.json();
  const otpApi = auth.method("email_otp");

  const res = await otpApi.request(
    { email },
    {
      requestId: crypto.randomUUID(),
      ip: getClientAddress(),
      userAgent: request.headers.get("user-agent") ?? undefined,
    },
  );

  if (!res.ok) {
    return json(
      { code: res.error.code, issues: res.issues },
      { status: res.error.status },
    );
  }

  return json({
    challengeId: res.data.challengeId,
    disposition: res.data.disposition,
  });
};
```

#### `src/routes/auth/otp/verify/+server.ts`

```ts
import { dev } from "$app/environment";
import { json } from "@sveltejs/kit";
import type { RequestHandler } from "./$types";
import { auth } from "$lib/server/auth";

const SESSION_COOKIE = "sid";

export const POST: RequestHandler = async ({
  request,
  cookies,
  getClientAddress,
}) => {
  const { challengeId, code } = await request.json();

  const res = await auth.authenticate(
    {
      method: "email_otp",
      challengeId,
      code,
    },
    {
      requestId: crypto.randomUUID(),
      ip: getClientAddress(),
      userAgent: request.headers.get("user-agent") ?? undefined,
    },
  );

  if (!res.ok) {
    return json(
      { code: res.error.code, issues: res.issues },
      { status: res.error.status },
    );
  }

  cookies.set(SESSION_COOKIE, res.sessionId, {
    httpOnly: true,
    secure: !dev,
    sameSite: "lax",
    path: "/",
    maxAge: 60 * 60 * 24 * 30,
  });

  return json({ user: res.user });
};
```

#### `src/hooks.server.ts`

```ts
import type { Handle } from "@sveltejs/kit";
import { auth } from "$lib/server/auth";

export const handle: Handle = async ({ event, resolve }) => {
  const sessionId = event.cookies.get("sid");
  if (!sessionId) return resolve(event);

  const session = await auth.validateSession(sessionId, {
    requestId: crypto.randomUUID(),
    ip: event.getClientAddress(),
    userAgent: event.request.headers.get("user-agent") ?? undefined,
  });

  if (!session.ok) {
    event.cookies.delete("sid", { path: "/" });
    return resolve(event);
  }

  event.locals.userId = session.userId;
  return resolve(event);
};
```

#### `src/routes/auth/logout/+server.ts`

```ts
import { json } from "@sveltejs/kit";
import type { RequestHandler } from "./$types";
import { auth } from "$lib/server/auth";

export const POST: RequestHandler = async ({
  cookies,
  request,
  getClientAddress,
}) => {
  const sessionId = cookies.get("sid");
  if (sessionId) {
    await auth.signOut(sessionId, {
      requestId: crypto.randomUUID(),
      ip: getClientAddress(),
      userAgent: request.headers.get("user-agent") ?? undefined,
    });
  }

  cookies.delete("sid", { path: "/" });
  return json({ ok: true });
};
```

#### `src/app.d.ts` (locals typing)

```ts
declare global {
  namespace App {
    interface Locals {
      userId?: string;
    }
  }
}

export {};
```

Both examples share the same core pattern:

- Configure adapters + plugins once.
- Use framework endpoints/actions to call `register`/`authenticate`/plugin APIs.
- Persist `sessionId` in secure cookie.
- Validate session on server for protected requests.
