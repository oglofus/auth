import type {
  MembershipBase,
  OrganizationBase,
  OrganizationRoleCatalog,
  ProfileCompletionState,
  SecondFactorMethod,
  Session,
  SignInMethodHint,
  StripeCustomerRecord,
  StripeSubject,
  StripeSubscriptionSnapshot,
  UserBase,
} from "./model.js";

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
  consume(key: string, limit: number, windowSeconds: number): Promise<RateLimitResult>;
}

export interface AuditRecord {
  action: string;
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

export interface PendingProfileRecord<U extends UserBase> extends ProfileCompletionState<U> {
  expiresAt: Date;
  consumedAt: Date | null;
}

export interface PendingProfileAdapter<U extends UserBase> {
  create(record: PendingProfileRecord<U>): Promise<void>;
  findById(pendingProfileId: string): Promise<MaybeFound<PendingProfileRecord<U>>>;
  consume(pendingProfileId: string): Promise<boolean>;
}

export interface IdempotencyAdapter {
  checkAndSet(key: string, ttlSeconds: number): Promise<boolean>;
}

export interface OrganizationAdapter<O extends OrganizationBase> {
  create(input: Omit<O, "id" | "createdAt" | "updatedAt">): Promise<O>;
  findById(organizationId: string): Promise<MaybeFound<O>>;
  findBySlug(slug: string): Promise<MaybeFound<O>>;
  update(organizationId: string, patch: Partial<O>): Promise<MaybeFound<O>>;
}

export interface MembershipAdapter<Role extends string, M extends MembershipBase<Role>> {
  create(input: Omit<M, "id" | "createdAt" | "updatedAt">): Promise<M>;
  findById(membershipId: string): Promise<MaybeFound<M>>;
  findByUserAndOrganization(userId: string, organizationId: string): Promise<MaybeFound<M>>;
  listByUser(userId: string): Promise<M[]>;
  listByOrganization(organizationId: string): Promise<M[]>;
  setRole(membershipId: string, role: Role): Promise<MaybeFound<M>>;
  setStatus(membershipId: string, status: M["status"]): Promise<MaybeFound<M>>;
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
  findActiveByTokenHash(tokenHash: string): Promise<MaybeFound<OrganizationInvite<Role>>>;
  consume(inviteId: string): Promise<boolean>;
  revoke(inviteId: string): Promise<void>;
}

export interface OrganizationEntitlementsAdapter<Feature extends string, LimitKey extends string> {
  getFeatureOverrides(organizationId: string): Promise<Partial<Record<Feature, boolean>>>;
  getLimitOverrides(organizationId: string): Promise<Partial<Record<LimitKey, number>>>;
  setFeatureOverride(organizationId: string, feature: Feature, enabled: boolean): Promise<void>;
  setLimitOverride(organizationId: string, key: LimitKey, value: number): Promise<void>;
}

export interface StripeCustomerAdapter {
  findBySubject(subject: StripeSubject): Promise<MaybeFound<StripeCustomerRecord>>;
  findByStripeCustomerId(stripeCustomerId: string): Promise<MaybeFound<StripeCustomerRecord>>;
  create(record: StripeCustomerRecord): Promise<void>;
  updateByStripeCustomerId(stripeCustomerId: string, patch: Partial<StripeCustomerRecord>): Promise<void>;
}

export interface StripeSubscriptionAdapter<Feature extends string, LimitKey extends string> {
  findActiveBySubject(subject: StripeSubject): Promise<MaybeFound<StripeSubscriptionSnapshot<Feature, LimitKey>>>;
  findByStripeSubscriptionId(
    stripeSubscriptionId: string,
  ): Promise<MaybeFound<StripeSubscriptionSnapshot<Feature, LimitKey>>>;
  listBySubject(subject: StripeSubject): Promise<StripeSubscriptionSnapshot<Feature, LimitKey>[]>;
  upsert(snapshot: StripeSubscriptionSnapshot<Feature, LimitKey>): Promise<void>;
}

export interface StripeWebhookEventAdapter {
  hasProcessed(eventId: string): Promise<boolean>;
  markProcessed(input: { eventId: string; processedAt: Date; type: string }): Promise<void>;
}

export interface StripeTrialUsageAdapter {
  hasUsedTrial(input: { subject: StripeSubject; planKey: string }): Promise<boolean>;
  markUsedTrial(input: { subject: StripeSubject; planKey: string; usedAt: Date }): Promise<void>;
}

export interface OrganizationInviteDeliveryPayload<Role extends string = string> {
  email: string;
  organizationName: string;
  inviteLink: string;
  expiresAt: Date;
  role: Role;
  requestId?: string;
  locale?: string;
}

export interface OrganizationInviteDeliveryHandler<Role extends string = string> {
  send(payload: OrganizationInviteDeliveryPayload<Role>): Promise<DeliveryResult>;
}

export type DeliveryChannel = string;

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
  createChallenge(input: { userId: string; email: string; codeHash: string; expiresAt: Date }): Promise<OtpChallenge>;
  findChallengeById(challengeId: string): Promise<MaybeFound<OtpChallenge>>;
  consumeChallenge(challengeId: string): Promise<boolean>;
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
  createToken(input: { userId?: string; email: string; tokenHash: string; expiresAt: Date }): Promise<MagicLinkToken>;
  findActiveTokenByHash(tokenHash: string): Promise<MaybeFound<MagicLinkToken>>;
  consumeToken(tokenId: string): Promise<boolean>;
}

export interface MagicLinkPluginHandlers {
  links: MagicLinkAdapter;
  delivery: MagicLinkDeliveryHandler;
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
  findByCredentialId(credentialId: string): Promise<MaybeFound<PasskeyCredential>>;
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

export interface SessionAdapter {
  create(session: Session): Promise<void>;
  findById(id: string): Promise<MaybeFound<Session>>;
  revoke(id: string): Promise<void>;
  revokeAllForUser(userId: string): Promise<void>;
}

export interface OrganizationSessionAdapter {
  setActiveOrganization(sessionId: string, organizationId?: string): Promise<MaybeFound<Session>>;
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
