import type { CoreAdapters, OrganizationsPluginHandlers } from "./adapters.js";
import type {
  AccountDiscoveryMode,
  AuthRequestContext,
  CompleteProfileInput,
  DiscoverAccountDecision,
  DiscoverAccountInput,
  MembershipBase,
  OrganizationBase,
  OrganizationEntitlementSnapshot,
  ProfileCompletionState,
  SecondFactorMethod,
  StripeBillingCycle,
  StripeEntitlementSnapshot,
  StripePlan,
  StripeSubject,
  StripeSubscriptionSnapshot,
  TwoFactorVerifyInput,
  UserBase,
} from "./model.js";
import type { AuthResult, OperationResult } from "./results.js";

export interface AuthPluginContext<U extends UserBase> {
  adapters: CoreAdapters<U>;
  now(): Date;
  security?: AuthSecurityConfig;
  request?: AuthRequestContext;
  getPluginApi?<T = unknown>(method: string): T | null;
}

export interface BasePlugin<Method extends string, U extends UserBase, ExposedApi extends object = {}> {
  kind: "auth_method" | "domain";
  method: Method;
  version: string;
  createApi?: (ctx: Omit<AuthPluginContext<U>, "request">) => ExposedApi;
}

export interface CompletePendingProfileInput<U extends UserBase> {
  record: ProfileCompletionState<U>;
  user: U;
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
    authenticate?: (input: unknown) => AuthenticateInput;
    register?: (input: unknown) => RegisterInput;
  };
  issueFields?: {
    authenticate: readonly Extract<keyof AuthenticateInput, string>[];
    register?: readonly Extract<keyof RegisterInput, string>[];
  };
  register?: (ctx: AuthPluginContext<U>, input: RegisterInput) => Promise<OperationResult<{ user: U }>>;
  authenticate: (ctx: AuthPluginContext<U>, input: AuthenticateInput) => Promise<OperationResult<{ user: U }>>;
  completePendingProfile?: (
    ctx: AuthPluginContext<U>,
    input: CompletePendingProfileInput<U>,
  ) => Promise<OperationResult<void>>;
}

export interface DomainPlugin<
  Method extends string,
  U extends UserBase,
  ExposedApi extends object = {},
> extends BasePlugin<Method, U, ExposedApi> {
  kind: "domain";
}

export interface TwoFactorEvaluateResult {
  required: boolean;
  pendingAuthId?: string;
  availableSecondFactors?: SecondFactorMethod[];
}

export interface TwoFactorPluginApi<U extends UserBase> {
  evaluatePrimary(
    input: { user: U; primaryMethod: string },
    request?: AuthRequestContext,
  ): Promise<OperationResult<TwoFactorEvaluateResult>>;
  verify(input: TwoFactorVerifyInput, request?: AuthRequestContext): Promise<OperationResult<{ user: U }>>;
  beginTotpEnrollment(userId: string): Promise<OperationResult<{ enrollmentId: string; otpauthUri: string }>>;
  confirmTotpEnrollment(input: { enrollmentId: string; code: string }): Promise<OperationResult<{ enabled: true }>>;
  regenerateRecoveryCodes(userId: string): Promise<OperationResult<{ codes: string[] }>>;
}

export interface EmailOtpPluginApi {
  request(
    input: { email: string; locale?: string },
    request?: AuthRequestContext,
  ): Promise<OperationResult<{ disposition: "sent" | "queued"; challengeId: string }>>;
}

export interface MagicLinkPluginApi {
  request(
    input: { email: string; redirectTo?: string; locale?: string },
    request?: AuthRequestContext,
  ): Promise<OperationResult<{ disposition: "sent" | "queued"; tokenId: string }>>;
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
  ): Promise<OperationResult<{ inviteId: string; disposition: "sent" | "queued" }>>;
  acceptInvite(
    input: { token: string; userId: string },
    request?: AuthRequestContext,
  ): Promise<OperationResult<{ organizationId: string; membership: M }>>;
  setActiveOrganization(
    input: { sessionId: string; organizationId?: string },
    request?: AuthRequestContext,
  ): Promise<OperationResult<{ sessionId: string; activeOrganizationId: string | null }>>;
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
  ): Promise<OperationResult<OrganizationEntitlementSnapshot<Feature, LimitKey>>>;
  setFeatureOverride(
    input: { organizationId: string; feature: Feature; enabled: boolean },
    request?: AuthRequestContext,
  ): Promise<OperationResult<{ organizationId: string; feature: Feature; enabled: boolean }>>;
  setLimitOverride(
    input: { organizationId: string; key: LimitKey; value: number },
    request?: AuthRequestContext,
  ): Promise<OperationResult<{ organizationId: string; key: LimitKey; value: number }>>;
  checkPermission(
    input: { organizationId: string; userId: string; permission: Permission },
    request?: AuthRequestContext,
  ): Promise<OperationResult<{ allowed: boolean; reason?: string }>>;
  checkFeature(
    input: { organizationId: string; userId: string; feature: Feature },
    request?: AuthRequestContext,
  ): Promise<OperationResult<{ enabled: boolean }>>;
  checkLimit(
    input: { organizationId: string; userId: string; key: LimitKey; amount?: number },
    request?: AuthRequestContext,
  ): Promise<OperationResult<{ allowed: boolean; remaining?: number }>>;
}

export interface StripePluginApi<Feature extends string, LimitKey extends string> {
  createCheckoutSession(input: {
    subject: StripeSubject;
    planKey: string;
    billingCycle: StripeBillingCycle;
    successUrl: string;
    cancelUrl: string;
    seats?: number;
    locale?: string;
    metadata?: Record<string, string>;
  }): Promise<OperationResult<{ url: string; checkoutSessionId: string }>>;
  createBillingPortalSession(input: {
    subject: StripeSubject;
    returnUrl: string;
    locale?: string;
  }): Promise<OperationResult<{ url: string }>>;
  getSubscription(input: {
    subject: StripeSubject;
  }): Promise<OperationResult<{ subscription: StripeSubscriptionSnapshot<Feature, LimitKey> | null }>>;
  listSubscriptions(input: {
    subject: StripeSubject;
  }): Promise<OperationResult<{ subscriptions: StripeSubscriptionSnapshot<Feature, LimitKey>[] }>>;
  cancelSubscription(input: {
    subject: StripeSubject;
    subscriptionId?: string;
    atPeriodEnd?: boolean;
  }): Promise<OperationResult<{ subscription: StripeSubscriptionSnapshot<Feature, LimitKey> }>>;
  resumeSubscription(input: {
    subject: StripeSubject;
    subscriptionId?: string;
  }): Promise<OperationResult<{ subscription: StripeSubscriptionSnapshot<Feature, LimitKey> }>>;
  changePlan(input: {
    subject: StripeSubject;
    planKey: string;
    billingCycle: StripeBillingCycle;
    subscriptionId?: string;
    seats?: number;
    scheduleAtPeriodEnd?: boolean;
  }): Promise<OperationResult<{ subscription: StripeSubscriptionSnapshot<Feature, LimitKey> }>>;
  getEntitlements(input: {
    subject: StripeSubject;
  }): Promise<OperationResult<StripeEntitlementSnapshot<Feature, LimitKey>>>;
  handleWebhook(input: {
    rawBody: string | Uint8Array;
    stripeSignature: string;
  }): Promise<OperationResult<{ processed: true; eventId: string }>>;
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
  handlers: OrganizationsPluginHandlers<O, Role, M, Permission, Feature, LimitKey>;
}

export type StripePlansResolver<Feature extends string, LimitKey extends string> =
  | readonly StripePlan<Feature, LimitKey>[]
  | (() => Promise<readonly StripePlan<Feature, LimitKey>[]>);

export type AuthSecurityRateLimitScope =
  | "discover"
  | "register"
  | "authenticate"
  | "emailOtpRequest"
  | "magicLinkRequest"
  | "otpVerify";

export interface AuthSecurityRateLimitPolicy {
  limit: number;
  windowSeconds: number;
}

export interface AuthSecurityConfig {
  rateLimits?: Partial<Record<AuthSecurityRateLimitScope, AuthSecurityRateLimitPolicy>>;
  oauth2IdempotencyTtlSeconds?: number;
}

export type AnyMethodPlugin<U extends UserBase> = AuthMethodPlugin<string, any, any, U, any>;
export type AnyDomainPlugin<U extends UserBase> = DomainPlugin<string, U, any>;
export type AnyPlugin<U extends UserBase> = AnyMethodPlugin<U> | AnyDomainPlugin<U>;

type MethodPlugins<P extends readonly AnyPlugin<any>[]> = Extract<P[number], AnyMethodPlugin<any>>;

export type RegisterInputFromPlugins<P extends readonly AnyPlugin<any>[]> =
  MethodPlugins<P> extends infer Pl
    ? Pl extends { supports: { register: true } }
      ? Pl extends AuthMethodPlugin<any, infer R, any, any, any>
        ? R
        : never
      : never
    : never;

export type AuthenticateInputFromPlugins<P extends readonly AnyPlugin<any>[]> =
  MethodPlugins<P> extends AuthMethodPlugin<any, any, infer A, any, any> ? A : never;

export type PluginApiMap<P extends readonly AnyPlugin<any>[]> = {
  [M in P[number]["method"]]: Extract<P[number], { method: M }> extends {
    createApi: (...args: any[]) => infer Api;
  }
    ? Api
    : never;
};

export type PluginMethodsWithApi<P extends readonly AnyPlugin<any>[]> = {
  [M in keyof PluginApiMap<P>]: PluginApiMap<P>[M] extends never ? never : M;
}[keyof PluginApiMap<P>];

export interface AuthConfig<U extends UserBase, P extends readonly AnyPlugin<U>[]> {
  adapters: CoreAdapters<U>;
  plugins: P;
  accountDiscovery?: {
    mode?: AccountDiscoveryMode;
  };
  normalize?: {
    email?: (value: string) => string;
  };
  session?: {
    ttlSeconds?: number;
  };
  security?: AuthSecurityConfig;
  validateConfigOnStart?: boolean;
}

export interface AuthPublicApi<U extends UserBase, P extends readonly AnyPlugin<U>[]> {
  discover(
    input: DiscoverAccountInput,
    request?: AuthRequestContext,
  ): Promise<OperationResult<DiscoverAccountDecision>>;
  authenticate(input: AuthenticateInputFromPlugins<P>, request?: AuthRequestContext): Promise<AuthResult<U>>;
  register(input: RegisterInputFromPlugins<P>, request?: AuthRequestContext): Promise<AuthResult<U>>;
  method<M extends PluginMethodsWithApi<P>>(method: M): PluginApiMap<P>[M];
  verifySecondFactor(input: TwoFactorVerifyInput, request?: AuthRequestContext): Promise<AuthResult<U>>;
  completeProfile(input: CompleteProfileInput<U>, request?: AuthRequestContext): Promise<AuthResult<U>>;
  validateSession(
    sessionId: string,
    request?: AuthRequestContext,
  ): Promise<{ ok: true; userId: string } | { ok: false }>;
  signOut(sessionId: string, request?: AuthRequestContext): Promise<void>;
}
