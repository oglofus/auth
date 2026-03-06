import { AuthError } from "../errors/index.js";
import {
  errorOperation,
  errorResult,
  successOperation,
  successResult,
  type AuthResult,
  type OperationResult,
} from "../types/results.js";
import {
  DEFAULT_SESSION_TTL_SECONDS,
  addSeconds,
  createId,
  normalizeEmailDefault,
  now,
} from "./utils.js";
import type {
  AuthConfig,
  AuthenticateInputFromPlugins,
  AuthPublicApi,
  AnyPlugin,
  AnyMethodPlugin,
  PluginApiMap,
  PluginMethodsWithApi,
  RegisterInputFromPlugins,
  TwoFactorPluginApi,
} from "../types/plugins.js";
import type {
  AuthRequestContext,
  CompleteProfileInput,
  DiscoverAccountDecision,
  DiscoverAccountInput,
  Session,
  TwoFactorRequiredMeta,
  TwoFactorVerifyInput,
  UserBase,
} from "../types/model.js";
import type { Issue } from "../issues/index.js";
import { createIssue } from "../issues/index.js";
import type { AuditRecord } from "../types/adapters.js";

const hasEmail = (value: unknown): value is { email: string } =>
  typeof value === "object" && value !== null && "email" in value && typeof (value as any).email === "string";

const toAuthError = (error: unknown): AuthError => {
  if (error instanceof AuthError) {
    return error;
  }

  return new AuthError("INTERNAL_ERROR", "Internal error.", 500);
};

type OrganizationPluginWithConfig = {
  __organizationConfig?: {
    handlers?: {
      organizationSessions?: unknown;
      roles?: Record<string, { inherits?: readonly string[]; system?: { owner?: boolean; default?: boolean } }>;
      defaultRole?: string;
    };
  };
};

export class OglofusAuth<
  U extends UserBase,
  P extends readonly AnyPlugin<U>[],
> implements AuthPublicApi<U, P> {
  private readonly pluginMap = new Map<string, P[number]>();
  private readonly apiMap = new Map<string, unknown>();
  private readonly normalizeEmail: (value: string) => string;

  constructor(private readonly config: AuthConfig<U, P>) {
    this.normalizeEmail = config.normalize?.email ?? normalizeEmailDefault;
    this.validatePlugins();

    for (const plugin of config.plugins) {
      this.pluginMap.set(plugin.method, plugin);
      if (plugin.createApi) {
        this.apiMap.set(
          plugin.method,
          plugin.createApi({
            adapters: this.config.adapters,
            now,
          }),
        );
      }
    }
  }

  public async discover(
    input: DiscoverAccountInput,
    request?: AuthRequestContext,
  ): Promise<OperationResult<DiscoverAccountDecision>> {
    const email = this.normalizeEmail(input.email);
    const mode = this.config.accountDiscovery?.mode ?? "private";

    if (mode === "private") {
      return successOperation({
        action: "continue_generic",
        reason: "DISCOVERY_PRIVATE",
        prefill: { email },
        messageKey: "auth.check_credentials_or_continue",
      });
    }

    const identity = this.config.adapters.identity;
    if (!identity) {
      return errorOperation(
        new AuthError(
          "PLUGIN_MISCONFIGURED",
          "identity adapter is required when accountDiscovery.mode is explicit.",
          500,
        ),
      );
    }

    const snapshot = await identity.findByEmail(email);

    if (input.intent === "login") {
      if (snapshot) {
        return successOperation({
          action: "continue_login",
          reason: "ACCOUNT_FOUND",
          prefill: { email },
          suggestedMethods: snapshot.methods,
        });
      }

      return successOperation({
        action: "redirect_register",
        reason: "ACCOUNT_NOT_FOUND",
        prefill: { email },
        messageKey: "auth.no_account",
      });
    }

    if (snapshot) {
      return successOperation({
        action: "redirect_login",
        reason: "ACCOUNT_EXISTS",
        prefill: { email },
        suggestedMethods: snapshot.methods,
        messageKey: "auth.account_exists",
      });
    }

    return successOperation({
      action: "redirect_register",
      reason: "ACCOUNT_NOT_FOUND",
      prefill: { email },
      messageKey: "auth.no_account",
    });
  }

  public async authenticate(
    input: AuthenticateInputFromPlugins<P>,
    request?: AuthRequestContext,
  ): Promise<AuthResult<U>> {
    const method = (input as any).method as string;
    const plugin = this.getAuthMethodPlugin(method);
    if (!plugin) {
      return errorResult(new AuthError("METHOD_DISABLED", `Method ${method} is disabled.`, 400));
    }

    const normalized = this.normalizeAuthInput(input);
    const validated = this.runValidator(plugin.validators?.authenticate, normalized);
    if (!validated.ok) {
      return validated.result;
    }

    const ctx = this.makeContext(request);
    const result = await plugin.authenticate(ctx, validated.input as any);
    if (!result.ok) {
      await this.writeAudit({
        action: "authenticate",
        method,
        requestId: request?.requestId,
        success: false,
        errorCode: result.error.code,
      });
      return errorResult(result.error, result.issues);
    }

    const twoFactor = this.tryGetTwoFactorApi();
    if (twoFactor) {
      const evaluation = await twoFactor.evaluatePrimary(
        {
          user: result.data.user,
          primaryMethod: method,
        },
        request,
      );

      if (!evaluation.ok) {
        return errorResult(evaluation.error, evaluation.issues);
      }

      if (evaluation.data.required) {
        const meta: TwoFactorRequiredMeta = {
          pendingAuthId: evaluation.data.pendingAuthId ?? "",
          availableSecondFactors: evaluation.data.availableSecondFactors ?? [],
        };

        const error = new AuthError(
          "TWO_FACTOR_REQUIRED",
          "Second factor required.",
          401,
          [],
          meta as unknown as Record<string, unknown>,
        ) as AuthError & { code: "TWO_FACTOR_REQUIRED"; meta: TwoFactorRequiredMeta };

        await this.writeAudit({
          action: "authenticate",
          method,
          requestId: request?.requestId,
          success: false,
          errorCode: error.code,
          userId: result.data.user.id,
        });

        return errorResult(error, result.issues);
      }
    }

    const sessionId = await this.createSession(result.data.user.id);
    await this.writeAudit({
      action: "authenticate",
      method,
      requestId: request?.requestId,
      success: true,
      userId: result.data.user.id,
    });

    return successResult(result.data.user, sessionId, result.issues);
  }

  public async register(
    input: RegisterInputFromPlugins<P>,
    request?: AuthRequestContext,
  ): Promise<AuthResult<U>> {
    const method = (input as any).method as string;
    const plugin = this.getAuthMethodPlugin(method);
    if (!plugin) {
      return errorResult(new AuthError("METHOD_DISABLED", `Method ${method} is disabled.`, 400));
    }

    if (!plugin.supports.register || !plugin.register) {
      return errorResult(
        new AuthError("METHOD_NOT_REGISTERABLE", `Method ${method} does not support register.`, 400),
      );
    }

    const normalized = this.normalizeAuthInput(input);
    const validated = this.runValidator(plugin.validators?.register, normalized);
    if (!validated.ok) {
      return validated.result;
    }

    const result = await plugin.register(this.makeContext(request), validated.input as any);
    if (!result.ok) {
      await this.writeAudit({
        action: "register",
        method,
        requestId: request?.requestId,
        success: false,
        errorCode: result.error.code,
      });
      return errorResult(result.error, result.issues);
    }

    const sessionId = await this.createSession(result.data.user.id);
    await this.writeAudit({
      action: "register",
      method,
      requestId: request?.requestId,
      success: true,
      userId: result.data.user.id,
    });

    return successResult(result.data.user, sessionId, result.issues);
  }

  public method<M extends PluginMethodsWithApi<P>>(method: M): PluginApiMap<P>[M] {
    if (!this.apiMap.has(method as string)) {
      throw new AuthError("METHOD_DISABLED", `No API exposed for method ${String(method)}.`, 400);
    }

    return this.apiMap.get(method as string) as PluginApiMap<P>[M];
  }

  public async verifySecondFactor(
    input: TwoFactorVerifyInput,
    request?: AuthRequestContext,
  ): Promise<AuthResult<U>> {
    const twoFactor = this.tryGetTwoFactorApi();
    if (!twoFactor) {
      return errorResult(new AuthError("METHOD_DISABLED", "two_factor plugin is not enabled.", 400));
    }

    const result = await twoFactor.verify(input, request);
    if (!result.ok) {
      return errorResult(result.error, result.issues);
    }

    const sessionId = await this.createSession(result.data.user.id);
    return successResult(result.data.user, sessionId, result.issues);
  }

  public async completeProfile(
    input: CompleteProfileInput<U>,
    request?: AuthRequestContext,
  ): Promise<AuthResult<U>> {
    const pending = this.config.adapters.pendingProfiles;
    if (!pending) {
      return errorResult(
        new AuthError("PLUGIN_MISCONFIGURED", "pendingProfiles adapter is not configured.", 500),
      );
    }

    const record = await pending.findById(input.pendingProfileId);
    if (!record || record.consumedAt || record.expiresAt.getTime() <= now().getTime()) {
      return errorResult(
        new AuthError("PROFILE_COMPLETION_EXPIRED", "Profile completion has expired.", 400),
      );
    }

    const missingIssues: Issue[] = [];
    for (const field of record.missingFields) {
      const value = (input.profile as Record<string, unknown>)[field];
      if (value === undefined || value === null || (typeof value === "string" && value.trim() === "")) {
        missingIssues.push(createIssue(`${String(field)} is required`, ["profile", field]));
      }
    }

    if (missingIssues.length > 0) {
      return errorResult(
        new AuthError("INVALID_INPUT", "Missing required profile fields.", 400, missingIssues),
        missingIssues,
      );
    }

    const consumed = await pending.consume(input.pendingProfileId);
    if (!consumed) {
      return errorResult(
        new AuthError("PROFILE_COMPLETION_EXPIRED", "Profile completion has expired.", 400),
      );
    }

    const email = record.email ? this.normalizeEmail(record.email) : undefined;
    const merged = {
      ...record.prefill,
      ...input.profile,
      ...(email ? { email } : {}),
    } as Record<string, unknown>;

    if (merged.emailVerified === undefined) {
      merged.emailVerified = false;
    }

    let user: U;
    if (email) {
      const existing = await this.config.adapters.users.findByEmail(email);
      if (existing) {
        const updated = await this.config.adapters.users.update(existing.id, merged as Partial<U>);
        if (!updated) {
          return errorResult(new AuthError("USER_NOT_FOUND", "User not found.", 404));
        }
        user = updated;
      } else {
        user = await this.config.adapters.users.create(
          merged as Omit<U, "id" | "createdAt" | "updatedAt">,
        );
      }
    } else {
      user = await this.config.adapters.users.create(
        merged as Omit<U, "id" | "createdAt" | "updatedAt">,
      );
    }

    const sessionId = await this.createSession(user.id);
    return successResult(user, sessionId);
  }

  public async validateSession(
    sessionId: string,
    _request?: AuthRequestContext,
  ): Promise<{ ok: true; userId: string } | { ok: false }> {
    const session = await this.config.adapters.sessions.findById(sessionId);
    if (!session) {
      return { ok: false };
    }

    if (session.revokedAt && session.revokedAt.getTime() <= now().getTime()) {
      return { ok: false };
    }

    if (session.expiresAt.getTime() <= now().getTime()) {
      return { ok: false };
    }

    return { ok: true, userId: session.userId };
  }

  public async signOut(sessionId: string, request?: AuthRequestContext): Promise<void> {
    await this.config.adapters.sessions.revoke(sessionId);
    await this.writeAudit({
      action: "session_revoke",
      requestId: request?.requestId,
      success: true,
    });
  }

  private normalizeAuthInput<T>(input: T): T {
    if (!hasEmail(input)) {
      return input;
    }

    return {
      ...(input as Record<string, unknown>),
      email: this.normalizeEmail(input.email),
    } as T;
  }

  private makeContext(request?: AuthRequestContext) {
    return {
      adapters: this.config.adapters,
      now,
      request,
    };
  }

  private async createSession(userId: string): Promise<string> {
    const id = createId();
    const ttl = this.config.session?.ttlSeconds ?? DEFAULT_SESSION_TTL_SECONDS;

    const session: Session = {
      id,
      userId,
      createdAt: now(),
      expiresAt: addSeconds(now(), ttl),
    };

    await this.config.adapters.sessions.create(session);
    return id;
  }

  private getAuthMethodPlugin(method: string): AnyMethodPlugin<U> | null {
    const plugin = this.pluginMap.get(method);
    if (!plugin || plugin.kind !== "auth_method") {
      return null;
    }

    return plugin as AnyMethodPlugin<U>;
  }

  private tryGetTwoFactorApi(): TwoFactorPluginApi<U> | null {
    const api = this.apiMap.get("two_factor");
    if (!api) {
      return null;
    }

    return api as TwoFactorPluginApi<U>;
  }

  private runValidator<T>(
    validator: ((input: unknown) => T) | undefined,
    input: unknown,
  ):
    | { ok: true; input: T }
    | { ok: false; result: AuthResult<U> } {
    if (!validator) {
      return { ok: true, input: input as T };
    }

    try {
      return {
        ok: true,
        input: validator(input),
      };
    } catch {
      return {
        ok: false,
        result: errorResult(new AuthError("INVALID_INPUT", "Invalid input payload.", 400)),
      };
    }
  }

  private validatePlugins(): void {
    const methods = new Set<string>();
    let twoFactorCount = 0;
    let organizationsCount = 0;

    for (const plugin of this.config.plugins) {
      if (methods.has(plugin.method)) {
        throw new AuthError(
          "PLUGIN_METHOD_CONFLICT",
          `Plugin method conflict for '${plugin.method}'.`,
          500,
        );
      }
      methods.add(plugin.method);

      if (plugin.method === "two_factor") {
        twoFactorCount += 1;
      }

      if (plugin.method === "organizations") {
        organizationsCount += 1;
      }

      if (plugin.kind === "auth_method") {
        if (plugin.supports.register && !plugin.register) {
          throw new AuthError(
            "PLUGIN_MISCONFIGURED",
            `Plugin '${plugin.method}' declares register support but no register handler.`,
            500,
          );
        }

        if (!plugin.supports.register && plugin.register) {
          throw new AuthError(
            "PLUGIN_MISCONFIGURED",
            `Plugin '${plugin.method}' disables register but exposes register handler.`,
            500,
          );
        }

        if (plugin.validators && !plugin.validators.authenticate) {
          throw new AuthError(
            "PLUGIN_MISCONFIGURED",
            `Plugin '${plugin.method}' validators missing authenticate parser.`,
            500,
          );
        }

        if (plugin.validators && plugin.supports.register && !plugin.validators.register) {
          throw new AuthError(
            "PLUGIN_MISCONFIGURED",
            `Plugin '${plugin.method}' validators missing register parser.`,
            500,
          );
        }
      }
    }

    if (twoFactorCount > 1) {
      throw new AuthError("PLUGIN_MISCONFIGURED", "At most one two_factor plugin is allowed.", 500);
    }

    if (organizationsCount > 1) {
      throw new AuthError(
        "PLUGIN_MISCONFIGURED",
        "At most one organizations plugin is allowed.",
        500,
      );
    }

    if ((this.config.accountDiscovery?.mode ?? "private") === "explicit" && !this.config.adapters.identity) {
      throw new AuthError(
        "PLUGIN_MISCONFIGURED",
        "identity adapter is required when accountDiscovery.mode is explicit.",
        500,
      );
    }

    const orgPlugin = this.config.plugins.find(
      (plugin) => plugin.method === "organizations",
    ) as (P[number] & OrganizationPluginWithConfig) | undefined;

    if (orgPlugin && !orgPlugin.__organizationConfig?.handlers?.organizationSessions) {
      throw new AuthError(
        "PLUGIN_MISCONFIGURED",
        "organizations plugin requires handlers.organizationSessions.",
        500,
      );
    }

    if (this.config.validateConfigOnStart) {
      const roleConfig = orgPlugin?.__organizationConfig?.handlers?.roles;
      const defaultRole = orgPlugin?.__organizationConfig?.handlers?.defaultRole;

      if (roleConfig && defaultRole) {
        const entries = Object.entries(roleConfig);
        const defaultRoles = entries.filter(([, role]) => role.system?.default).map(([role]) => role);
        const ownerRoles = entries.filter(([, role]) => role.system?.owner).map(([role]) => role);

        if (defaultRoles.length !== 1) {
          throw new AuthError(
            "PLUGIN_MISCONFIGURED",
            "Organization roles must define exactly one system.default role.",
            500,
          );
        }

        if (ownerRoles.length < 1) {
          throw new AuthError(
            "PLUGIN_MISCONFIGURED",
            "Organization roles must define at least one owner role.",
            500,
          );
        }

        if (defaultRoles[0] !== defaultRole) {
          throw new AuthError(
            "PLUGIN_MISCONFIGURED",
            "handlers.defaultRole must match the role marked system.default.",
            500,
          );
        }

        if (ownerRoles.includes(defaultRole)) {
          throw new AuthError(
            "PLUGIN_MISCONFIGURED",
            "Default organization role cannot be owner.",
            500,
          );
        }

        this.assertAcyclicRoleInheritance(roleConfig);
      }
    }
  }

  private assertAcyclicRoleInheritance(
    roles: Record<string, { inherits?: readonly string[] }>,
  ): void {
    const visiting = new Set<string>();
    const visited = new Set<string>();

    const visit = (role: string): void => {
      if (visited.has(role)) {
        return;
      }

      if (visiting.has(role)) {
        throw new AuthError(
          "PLUGIN_MISCONFIGURED",
          `Cycle detected in role inheritance at '${role}'.`,
          500,
        );
      }

      visiting.add(role);
      for (const inherited of roles[role]?.inherits ?? []) {
        visit(inherited);
      }
      visiting.delete(role);
      visited.add(role);
    };

    for (const role of Object.keys(roles)) {
      visit(role);
    }
  }

  private async writeAudit(input: Omit<AuditRecord, "timestamp">): Promise<void> {
    if (!this.config.adapters.audit) {
      return;
    }

    try {
      await this.config.adapters.audit.write({
        ...input,
        timestamp: now(),
      });
    } catch {
      // intentionally ignore audit failures
    }
  }
}
