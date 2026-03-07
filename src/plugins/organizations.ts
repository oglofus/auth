import { addSeconds, createId, createToken, deterministicTokenHash } from "../core/utils.js";
import { AuthError } from "../errors/index.js";
import { createIssue } from "../issues/index.js";
import type {
  MembershipBase,
  OrganizationBase,
  OrganizationRoleCatalog,
  StripeEntitlementSnapshot,
  UserBase,
} from "../types/model.js";
import type {
  DomainPlugin,
  OrganizationsPluginApi,
  OrganizationsPluginConfig,
  StripePluginApi,
} from "../types/plugins.js";
import { errorOperation, successOperation, type OperationResult } from "../types/results.js";

export type OrganizationsPluginOptions<
  O extends OrganizationBase,
  Role extends string,
  M extends MembershipBase<Role>,
  Permission extends string,
  Feature extends string,
  LimitKey extends string,
  RequiredOrgFields extends keyof O = never,
> = OrganizationsPluginConfig<O, Role, M, Permission, Feature, LimitKey, RequiredOrgFields> & {
  inviteBaseUrl: string;
  inviteTtlSeconds?: number;
  canAssignRole?: (input: { actorMembership: M; targetMembership: M; nextRole: Role }) => boolean | Promise<boolean>;
};

type ResolvedRole<Permission extends string, Feature extends string, LimitKey extends string> = {
  permissions: Set<Permission>;
  features: Partial<Record<Feature, boolean>>;
  limits: Partial<Record<LimitKey, number>>;
};

const normalizeEmail = (value: string): string => value.trim().toLowerCase();

const findOwnerRoles = <
  Role extends string,
  Permission extends string,
  Feature extends string,
  LimitKey extends string,
>(
  roles: OrganizationRoleCatalog<Role, Permission, Feature, LimitKey>,
): Role[] =>
  (Object.entries(roles) as Array<[Role, (typeof roles)[Role]]>)
    .filter(([, definition]) => definition.system?.owner)
    .map(([role]) => role);

const resolveRole = <Role extends string, Permission extends string, Feature extends string, LimitKey extends string>(
  role: Role,
  roles: OrganizationRoleCatalog<Role, Permission, Feature, LimitKey>,
  visited = new Set<Role>(),
): ResolvedRole<Permission, Feature, LimitKey> => {
  if (visited.has(role)) {
    return {
      permissions: new Set(),
      features: {},
      limits: {},
    };
  }

  visited.add(role);
  const definition = roles[role];
  if (!definition) {
    return {
      permissions: new Set(),
      features: {},
      limits: {},
    };
  }

  const resolved: ResolvedRole<Permission, Feature, LimitKey> = {
    permissions: new Set<Permission>(),
    features: {},
    limits: {},
  };

  for (const inherited of definition.inherits ?? []) {
    const nested = resolveRole(inherited, roles, visited);
    for (const permission of nested.permissions) {
      resolved.permissions.add(permission);
    }
    Object.assign(resolved.features, nested.features);
    Object.assign(resolved.limits, nested.limits);
  }

  for (const permission of definition.permissions) {
    resolved.permissions.add(permission);
  }

  Object.assign(resolved.features, definition.features ?? {});
  Object.assign(resolved.limits, definition.limits ?? {});

  return resolved;
};

export const organizationsPlugin = <
  U extends UserBase,
  O extends OrganizationBase,
  Role extends string,
  M extends MembershipBase<Role>,
  Permission extends string,
  Feature extends string,
  LimitKey extends string,
  RequiredOrgFields extends keyof O = never,
>(
  config: OrganizationsPluginOptions<O, Role, M, Permission, Feature, LimitKey, RequiredOrgFields>,
): DomainPlugin<
  "organizations",
  U,
  OrganizationsPluginApi<O, Role, M, Permission, Feature, LimitKey, RequiredOrgFields>,
  true
> => {
  const inviteTtl = config.inviteTtlSeconds ?? 7 * 24 * 60 * 60;
  const ownerRoles = findOwnerRoles(config.handlers.roles);

  const plugin: DomainPlugin<
    "organizations",
    U,
    OrganizationsPluginApi<O, Role, M, Permission, Feature, LimitKey, RequiredOrgFields>,
    true
  > & {
    __organizationConfig: OrganizationsPluginOptions<O, Role, M, Permission, Feature, LimitKey, RequiredOrgFields>;
  } = {
    kind: "domain",
    method: "organizations",
    version: "2.0.0",
    __organizationConfig: config,
    createApi: (ctx) => {
      const ensureActorMembership = async (userId: string, organizationId: string): Promise<OperationResult<M>> => {
        const membership = await config.handlers.memberships.findByUserAndOrganization(userId, organizationId);

        if (!membership || membership.status !== "active") {
          return errorOperation(
            new AuthError("MEMBERSHIP_FORBIDDEN", "Active membership is required for this organization.", 403),
          );
        }

        return successOperation(membership);
      };

      const ensureOwner = async (userId: string, organizationId: string): Promise<OperationResult<M>> => {
        const membershipRes = await ensureActorMembership(userId, organizationId);
        if (!membershipRes.ok) {
          return membershipRes;
        }

        if (!ownerRoles.includes(membershipRes.data.role)) {
          return errorOperation(new AuthError("MEMBERSHIP_FORBIDDEN", "Owner role required for this action.", 403));
        }

        return membershipRes;
      };

      const getEntitlementsInternal = async (
        organizationId: string,
        userId: string,
      ): Promise<
        OperationResult<{ features: Partial<Record<Feature, boolean>>; limits: Partial<Record<LimitKey, number>> }>
      > => {
        const membershipRes = await ensureActorMembership(userId, organizationId);
        if (!membershipRes.ok) {
          return membershipRes;
        }

        const resolved = resolveRole(membershipRes.data.role, config.handlers.roles);
        const stripeApi = ctx.getPluginApi?.<StripePluginApi<Feature, LimitKey>>("stripe") ?? null;
        let billingEntitlements: StripeEntitlementSnapshot<Feature, LimitKey> = {
          features: {},
          limits: {},
        };
        if (stripeApi) {
          const stripeEntitlements = await stripeApi.getEntitlements({
            subject: {
              kind: "organization",
              organizationId,
            },
          });
          if (!stripeEntitlements.ok) {
            return stripeEntitlements;
          }
          billingEntitlements = stripeEntitlements.data;
        }
        const featureOverrides = await config.handlers.entitlements.getFeatureOverrides(organizationId);
        const limitOverrides = await config.handlers.entitlements.getLimitOverrides(organizationId);

        return successOperation({
          features: {
            ...resolved.features,
            ...billingEntitlements.features,
            ...featureOverrides,
          },
          limits: {
            ...resolved.limits,
            ...billingEntitlements.limits,
            ...limitOverrides,
          },
        });
      };

      return {
        createOrganization: async (input, request) => {
          const actorUserId = request?.userId;
          if (!actorUserId) {
            return errorOperation(
              new AuthError("INVALID_INPUT", "request.userId is required.", 400, [
                createIssue("Actor user id is required", ["request", "userId"]),
              ]),
            );
          }

          const existing = await config.handlers.organizations.findBySlug(input.slug);
          if (existing) {
            return errorOperation(
              new AuthError("CONFLICT", "Organization slug is already taken.", 409, [
                createIssue("Slug already exists", ["slug"]),
              ]),
            );
          }

          const run = async () => {
            const orgPayload = {
              ...(input.profile ?? {}),
              slug: input.slug,
              name: input.name,
            } as Omit<O, "id" | "createdAt" | "updatedAt">;

            const organization = await config.handlers.organizations.create(orgPayload);
            const ownerRole = ownerRoles[0] ?? config.handlers.defaultRole;

            const membership = await config.handlers.memberships.create({
              organizationId: organization.id,
              userId: actorUserId,
              role: ownerRole,
              status: "active",
            } as Omit<M, "id" | "createdAt" | "updatedAt">);

            return { organization, membership };
          };

          const data = ctx.adapters.withTransaction ? await ctx.adapters.withTransaction(run) : await run();

          return successOperation(data);
        },
        inviteMember: async (input, request) => {
          const actorUserId = request?.userId;
          if (!actorUserId) {
            return errorOperation(new AuthError("INVALID_INPUT", "request.userId is required.", 400));
          }

          const owner = await ensureOwner(actorUserId, input.organizationId);
          if (!owner.ok) {
            return owner;
          }

          const organization = await config.handlers.organizations.findById(input.organizationId);
          if (!organization) {
            return errorOperation(new AuthError("ORGANIZATION_NOT_FOUND", "Organization not found.", 404));
          }

          const role = input.role ?? config.handlers.defaultRole;
          if (!config.handlers.roles[role]) {
            return errorOperation(new AuthError("ROLE_INVALID", "Unknown role.", 400));
          }

          const rawToken = createToken(32);
          const tokenHash = deterministicTokenHash(rawToken, "org_invite");
          const invite = {
            id: createId(),
            organizationId: input.organizationId,
            email: normalizeEmail(input.email),
            role,
            tokenHash,
            invitedByUserId: actorUserId,
            expiresAt: addSeconds(ctx.now(), inviteTtl),
            acceptedAt: null,
            revokedAt: null,
          };

          await config.handlers.invites.create(invite);

          const link = `${config.inviteBaseUrl}?token=${encodeURIComponent(rawToken)}`;
          const delivery = await config.handlers.inviteDelivery.send({
            email: invite.email,
            organizationName: organization.name,
            inviteLink: link,
            expiresAt: invite.expiresAt,
            role,
            requestId: request?.requestId,
            locale: input.locale,
          });

          if (!delivery.accepted) {
            return errorOperation(new AuthError("DELIVERY_FAILED", "Unable to deliver invite.", 502));
          }

          return successOperation({
            inviteId: invite.id,
            disposition: "sent" as const,
          });
        },
        acceptInvite: async (input) => {
          const invite = await config.handlers.invites.findActiveByTokenHash(
            deterministicTokenHash(input.token, "org_invite"),
          );

          if (!invite) {
            return errorOperation(new AuthError("ORGANIZATION_INVITE_INVALID", "Invalid invite token.", 400));
          }

          if (invite.expiresAt.getTime() <= ctx.now().getTime()) {
            return errorOperation(new AuthError("ORGANIZATION_INVITE_EXPIRED", "Invite token expired.", 400));
          }

          const user = await ctx.adapters.users.findById(input.userId);
          if (!user) {
            return errorOperation(new AuthError("USER_NOT_FOUND", "User not found.", 404));
          }

          if (normalizeEmail(user.email) !== normalizeEmail(invite.email)) {
            return errorOperation(
              new AuthError("MEMBERSHIP_FORBIDDEN", "Invite email does not match authenticated user.", 403),
            );
          }

          const consumed = await config.handlers.invites.consume(invite.id);
          if (!consumed) {
            return errorOperation(new AuthError("ORGANIZATION_INVITE_INVALID", "Invite already used/revoked.", 400));
          }

          const existing = await config.handlers.memberships.findByUserAndOrganization(
            input.userId,
            invite.organizationId,
          );

          let membership: M;
          if (existing) {
            const updatedRole = await config.handlers.memberships.setRole(existing.id, invite.role);
            if (!updatedRole) {
              return errorOperation(new AuthError("MEMBERSHIP_NOT_FOUND", "Membership not found.", 404));
            }
            membership = updatedRole;
            if (membership.status !== "active") {
              const updatedStatus = await config.handlers.memberships.setStatus(membership.id, "active");
              if (!updatedStatus) {
                return errorOperation(new AuthError("MEMBERSHIP_NOT_FOUND", "Membership not found.", 404));
              }
              membership = updatedStatus;
            }
          } else {
            membership = await config.handlers.memberships.create({
              organizationId: invite.organizationId,
              userId: input.userId,
              role: invite.role,
              status: "active",
            } as Omit<M, "id" | "createdAt" | "updatedAt">);
          }

          return successOperation({
            organizationId: invite.organizationId,
            membership,
          });
        },
        setActiveOrganization: async (input, request) => {
          const session = await ctx.adapters.sessions.findById(input.sessionId);
          if (!session) {
            return errorOperation(new AuthError("SESSION_NOT_FOUND", "Session not found.", 404));
          }

          if (input.organizationId) {
            const memberships = await config.handlers.memberships.listByUser(session.userId);
            const active = memberships.find(
              (membership) => membership.organizationId === input.organizationId && membership.status === "active",
            );

            if (!active) {
              return errorOperation(
                new AuthError("MEMBERSHIP_FORBIDDEN", "No active membership for organization.", 403),
              );
            }
          }

          const updatedSession = await config.handlers.organizationSessions.setActiveOrganization(
            input.sessionId,
            input.organizationId,
          );
          if (!updatedSession) {
            return errorOperation(new AuthError("SESSION_NOT_FOUND", "Session not found.", 404));
          }

          return successOperation({
            sessionId: input.sessionId,
            activeOrganizationId: updatedSession.activeOrganizationId ?? null,
          });
        },
        setMemberRole: async (input, request) => {
          const actorUserId = request?.userId;
          if (!actorUserId) {
            return errorOperation(new AuthError("INVALID_INPUT", "request.userId is required.", 400));
          }

          const owner = await ensureOwner(actorUserId, input.organizationId);
          if (!owner.ok) {
            return owner;
          }

          const target = await config.handlers.memberships.findById(input.membershipId);
          if (!target || target.organizationId !== input.organizationId) {
            return errorOperation(new AuthError("MEMBERSHIP_NOT_FOUND", "Membership not found.", 404));
          }

          if (!config.handlers.roles[input.role]) {
            return errorOperation(new AuthError("ROLE_INVALID", "Unknown role.", 400));
          }

          if (config.canAssignRole) {
            const allowed = await config.canAssignRole({
              actorMembership: owner.data,
              targetMembership: target,
              nextRole: input.role,
            });

            if (!allowed) {
              return errorOperation(new AuthError("ROLE_NOT_ASSIGNABLE", "Role assignment not allowed.", 403));
            }
          }

          const currentlyOwner = ownerRoles.includes(target.role);
          const nextIsOwner = ownerRoles.includes(input.role);
          if (currentlyOwner && !nextIsOwner) {
            const members = await config.handlers.memberships.listByOrganization(input.organizationId);
            const activeOwners = members.filter(
              (member) => member.status === "active" && ownerRoles.includes(member.role),
            );

            if (activeOwners.length <= 1) {
              return errorOperation(
                new AuthError("LAST_OWNER_GUARD", "Cannot remove/demote the last organization owner.", 409),
              );
            }
          }

          const membership = await config.handlers.memberships.setRole(input.membershipId, input.role);
          if (!membership) {
            return errorOperation(new AuthError("MEMBERSHIP_NOT_FOUND", "Membership not found.", 404));
          }
          return successOperation({ membership });
        },
        listMemberships: async (input) => {
          const memberships = await config.handlers.memberships.listByUser(input.userId);
          return successOperation({ memberships });
        },
        getEntitlements: async (input) => {
          return getEntitlementsInternal(input.organizationId, input.userId);
        },
        setFeatureOverride: async (input, request) => {
          const actorUserId = request?.userId;
          if (!actorUserId) {
            return errorOperation(new AuthError("INVALID_INPUT", "request.userId is required.", 400));
          }

          const owner = await ensureOwner(actorUserId, input.organizationId);
          if (!owner.ok) {
            return owner;
          }

          await config.handlers.entitlements.setFeatureOverride(input.organizationId, input.feature, input.enabled);

          return successOperation({
            organizationId: input.organizationId,
            feature: input.feature,
            enabled: input.enabled,
          });
        },
        setLimitOverride: async (input, request) => {
          const actorUserId = request?.userId;
          if (!actorUserId) {
            return errorOperation(new AuthError("INVALID_INPUT", "request.userId is required.", 400));
          }

          const owner = await ensureOwner(actorUserId, input.organizationId);
          if (!owner.ok) {
            return owner;
          }

          await config.handlers.entitlements.setLimitOverride(input.organizationId, input.key, input.value);

          return successOperation({
            organizationId: input.organizationId,
            key: input.key,
            value: input.value,
          });
        },
        checkPermission: async (input) => {
          const membership = await config.handlers.memberships.findByUserAndOrganization(
            input.userId,
            input.organizationId,
          );

          if (!membership || membership.status !== "active") {
            return successOperation({ allowed: false, reason: "membership_not_active" });
          }

          const resolved = resolveRole(membership.role, config.handlers.roles);
          const allowed = resolved.permissions.has(input.permission);

          return successOperation({
            allowed,
            reason: allowed ? undefined : "permission_denied",
          });
        },
        checkFeature: async (input) => {
          const entitlements = await getEntitlementsInternal(input.organizationId, input.userId);
          if (!entitlements.ok) {
            return entitlements;
          }

          return successOperation({ enabled: entitlements.data.features[input.feature] === true });
        },
        checkLimit: async (input) => {
          const entitlements = await getEntitlementsInternal(input.organizationId, input.userId);
          if (!entitlements.ok) {
            return entitlements;
          }

          const amount = input.amount ?? 1;
          const configured = entitlements.data.limits[input.key];
          if (configured === undefined) {
            return successOperation({ allowed: true });
          }

          const remaining = configured - amount;
          return successOperation({
            allowed: remaining >= 0,
            remaining,
          });
        },
      };
    },
  };

  return plugin;
};
