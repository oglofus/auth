import { Buffer } from "node:buffer";

import type Stripe from "stripe";
import { createId } from "../core/utils.js";
import { AuthError } from "../errors/index.js";
import type {
  StripeCustomerAdapter,
  StripeSubscriptionAdapter,
  StripeTrialUsageAdapter,
  StripeWebhookEventAdapter,
} from "../types/adapters.js";
import type {
  StripeBillingCycle,
  StripeCustomerRecord,
  StripePlan,
  StripeSubject,
  StripeSubscriptionSnapshot,
  UserBase,
} from "../types/model.js";
import type { DomainPlugin, StripePlansResolver, StripePluginApi } from "../types/plugins.js";
import { errorOperation, successOperation, type OperationResult } from "../types/results.js";

const SUBJECT_KIND_KEY = "oglofus_subject_kind";
const SUBJECT_ID_KEY = "oglofus_subject_id";
const PLAN_KEY_KEY = "oglofus_plan_key";
const BILLING_CYCLE_KEY = "oglofus_billing_cycle";

const ENTITLED_STATUSES = new Set<StripeSubscriptionSnapshot["status"]>(["trialing", "active"]);

type StripePluginHandlers<Feature extends string, LimitKey extends string> = {
  customers: StripeCustomerAdapter;
  subscriptions: StripeSubscriptionAdapter<Feature, LimitKey>;
  events: StripeWebhookEventAdapter;
  trials?: StripeTrialUsageAdapter;
};

export type StripePluginConfig<U extends UserBase, Feature extends string, LimitKey extends string> = {
  stripe: Stripe;
  webhookSecret: string;
  plans: StripePlansResolver<Feature, LimitKey>;
  handlers: StripePluginHandlers<Feature, LimitKey>;
  customerMode?: "user" | "organization" | "both";
};

type StripePlanCatalogEntry<Feature extends string, LimitKey extends string> = Omit<StripePlan<Feature, LimitKey>, "scope"> & {
  scope: StripeSubject["kind"];
};

type StripePlanCatalog<Feature extends string, LimitKey extends string> = readonly StripePlanCatalogEntry<Feature, LimitKey>[];

const subjectId = (subject: StripeSubject): string =>
  subject.kind === "user" ? subject.userId : subject.organizationId;

const subjectsEqual = (left: StripeSubject, right: StripeSubject): boolean =>
  left.kind === right.kind && subjectId(left) === subjectId(right);

const referenceForSubject = (subject: StripeSubject): `${StripeSubject["kind"]}:${string}` =>
  `${subject.kind}:${subjectId(subject)}`;

const metadataForSubject = (
  subject: StripeSubject,
  planKey: string,
  billingCycle: StripeBillingCycle,
  metadata?: Record<string, string>,
): Record<string, string> => ({
  ...(metadata ?? {}),
  [SUBJECT_KIND_KEY]: subject.kind,
  [SUBJECT_ID_KEY]: subjectId(subject),
  [PLAN_KEY_KEY]: planKey,
  [BILLING_CYCLE_KEY]: billingCycle,
});

const toDate = (value: number | null | undefined): Date | null | undefined =>
  value === null || value === undefined ? value : new Date(value * 1_000);

const toMetadataRecord = (metadata?: Stripe.Metadata | null): Record<string, string> => {
  if (!metadata) {
    return {};
  }

  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(metadata)) {
    if (typeof value === "string") {
      out[key] = value;
    }
  }
  return out;
};

const isAllowedByCustomerMode = (
  customerMode: NonNullable<StripePluginConfig<any, any, any>["customerMode"]>,
  subject: StripeSubject,
): boolean => {
  if (customerMode === "both") {
    return true;
  }

  return customerMode === subject.kind;
};

const validatePlan = <Feature extends string, LimitKey extends string>(
  plan: StripePlan<Feature, LimitKey>,
  customerMode: NonNullable<StripePluginConfig<any, Feature, LimitKey>["customerMode"]>,
) => {
  if (!plan.prices.monthly && !plan.prices.annual) {
    throw new AuthError("PLUGIN_MISCONFIGURED", `Stripe plan '${plan.key}' must define at least one price.`, 500);
  }

  if (
    !isAllowedByCustomerMode(
      customerMode,
      plan.scope === "user" ? { kind: "user", userId: "preview" } : { kind: "organization", organizationId: "preview" },
    )
  ) {
    throw new AuthError(
      "PLUGIN_MISCONFIGURED",
      `Stripe plan '${plan.key}' scope is incompatible with customerMode '${customerMode}'.`,
      500,
    );
  }

  if (plan.scope === "user" && plan.seats?.enabled) {
    throw new AuthError("PLUGIN_MISCONFIGURED", `Stripe plan '${plan.key}' cannot enable seats for user billing.`, 500);
  }

  if (plan.trial && plan.trial.days <= 0) {
    throw new AuthError("PLUGIN_MISCONFIGURED", `Stripe plan '${plan.key}' trial.days must be greater than zero.`, 500);
  }

  if (
    plan.seats?.enabled &&
    plan.seats.minimum !== undefined &&
    plan.seats.maximum !== undefined &&
    plan.seats.minimum > plan.seats.maximum
  ) {
    throw new AuthError(
      "PLUGIN_MISCONFIGURED",
      `Stripe plan '${plan.key}' seats.minimum cannot exceed seats.maximum.`,
      500,
    );
  }
};

const withSeatLimit = <LimitKey extends string>(
  limits: Partial<Record<LimitKey, number>>,
  seats: number | null | undefined,
  limitKey: LimitKey | undefined,
): Partial<Record<LimitKey, number>> => {
  if (limitKey === undefined || seats === null || seats === undefined) {
    return limits;
  }

  return {
    ...limits,
    [limitKey]: seats,
  };
};

const validatePlans = <Feature extends string, LimitKey extends string>(
  plans: readonly StripePlan<Feature, LimitKey>[],
  customerMode: NonNullable<StripePluginConfig<any, Feature, LimitKey>["customerMode"]>,
  trials: StripeTrialUsageAdapter | undefined,
) => {
  const keys = new Set<string>();
  let trialPlans = 0;

  for (const plan of plans) {
    validatePlan(plan, customerMode);
    if (keys.has(plan.key)) {
      throw new AuthError("PLUGIN_MISCONFIGURED", `Duplicate Stripe plan key '${plan.key}'.`, 500);
    }
    keys.add(plan.key);

    if (plan.trial) {
      trialPlans += 1;
    }
  }

  if (trialPlans > 0 && !trials) {
    throw new AuthError("PLUGIN_MISCONFIGURED", "Stripe plans with trial configuration require handlers.trials.", 500);
  }
};

const normalizeStatus = (status: Stripe.Subscription.Status): StripeSubscriptionSnapshot["status"] => status;

export const stripePlugin = <
  U extends UserBase,
  Feature extends string,
  LimitKey extends string,
  const Plans extends StripePlanCatalog<Feature, LimitKey>,
>(
  config: Omit<StripePluginConfig<U, Feature, LimitKey>, "plans"> & {
    plans: StripePlansResolver<Feature, LimitKey, Plans>;
  },
): DomainPlugin<"stripe", U, StripePluginApi<Feature, LimitKey>, true> => {
  const customerMode = config.customerMode ?? "both";
  if (Array.isArray(config.plans)) {
    validatePlans(config.plans, customerMode, config.handlers.trials);
  }

  let plansPromise: Promise<readonly StripePlan<Feature, LimitKey>[]> | null = null;

  const loadPlans = async (): Promise<readonly StripePlan<Feature, LimitKey>[]> => {
    if (!plansPromise) {
      plansPromise = (async () => {
        const resolved = typeof config.plans === "function" ? await config.plans() : config.plans;
        validatePlans(resolved, customerMode, config.handlers.trials);
        return resolved;
      })();
    }

    return plansPromise;
  };

  const resolvePlanByKey = async (planKey: string): Promise<StripePlan<Feature, LimitKey>> => {
    const plans = await loadPlans();
    const plan = plans.find((candidate) => candidate.key === planKey);
    if (!plan) {
      throw new AuthError("INVALID_INPUT", `Unknown Stripe plan '${planKey}'.`, 400);
    }

    return plan;
  };

  const resolvePlanByPriceId = async (
    priceId: string,
    fallbackPlanKey?: string,
  ): Promise<{
    plan: StripePlan<Feature, LimitKey>;
    billingCycle: StripeBillingCycle;
  }> => {
    const plans = await loadPlans();
    for (const plan of plans) {
      if (plan.prices.monthly?.priceId === priceId) {
        return { plan, billingCycle: "monthly" };
      }

      if (plan.prices.annual?.priceId === priceId) {
        return { plan, billingCycle: "annual" };
      }
    }

    if (fallbackPlanKey) {
      const fallback = plans.find((candidate) => candidate.key === fallbackPlanKey);
      if (fallback) {
        const billingCycle = fallback.prices.annual?.priceId === priceId ? "annual" : "monthly";
        return { plan: fallback, billingCycle };
      }
    }

    throw new AuthError("PLUGIN_MISCONFIGURED", `Unable to resolve Stripe plan for price '${priceId}'.`, 500);
  };

  const assertSubjectAllowed = (subject: StripeSubject) => {
    if (!isAllowedByCustomerMode(customerMode, subject)) {
      throw new AuthError("INVALID_INPUT", `Billing subject kind '${subject.kind}' is not enabled.`, 400);
    }
  };

  const assertPlanForSubject = (subject: StripeSubject, plan: StripePlan<Feature, LimitKey>) => {
    if (subject.kind !== plan.scope) {
      throw new AuthError("INVALID_INPUT", `Plan '${plan.key}' cannot be used for ${subject.kind} billing.`, 400);
    }
  };

  const resolveQuantity = (
    subject: StripeSubject,
    plan: StripePlan<Feature, LimitKey>,
    requestedSeats?: number,
  ): number | undefined => {
    if (!plan.seats?.enabled) {
      if (requestedSeats !== undefined) {
        throw new AuthError("INVALID_INPUT", "Seats are not supported for this plan.", 400);
      }
      return undefined;
    }

    if (subject.kind !== "organization") {
      throw new AuthError("INVALID_INPUT", "Seats are only supported for organizations.", 400);
    }

    const quantity = requestedSeats ?? plan.seats.minimum ?? 1;
    if (!Number.isInteger(quantity) || quantity <= 0) {
      throw new AuthError("INVALID_INPUT", "Seats must be a positive integer.", 400);
    }
    if (plan.seats.minimum !== undefined && quantity < plan.seats.minimum) {
      throw new AuthError("INVALID_INPUT", `Seats must be at least ${plan.seats.minimum}.`, 400);
    }
    if (plan.seats.maximum !== undefined && quantity > plan.seats.maximum) {
      throw new AuthError("INVALID_INPUT", `Seats must be at most ${plan.seats.maximum}.`, 400);
    }

    return quantity;
  };

  const createCustomerRecord = async (
    subject: StripeSubject,
    stripeCustomerId: string,
    now: Date,
  ): Promise<StripeCustomerRecord> => {
    const record: StripeCustomerRecord = {
      id: createId(),
      subject,
      stripeCustomerId,
      createdAt: now,
      updatedAt: now,
    };
    await config.handlers.customers.create(record);
    return record;
  };

  const ensureCustomer = async (
    ctx: Parameters<NonNullable<DomainPlugin<"stripe", U, StripePluginApi<Feature, LimitKey>>["createApi"]>>[0],
    subject: StripeSubject,
    now: Date,
  ): Promise<StripeCustomerRecord> => {
    const existing = await config.handlers.customers.findBySubject(subject);
    if (existing) {
      return existing;
    }

    let email: string | undefined;
    if (subject.kind === "user") {
      const user = await ctx.adapters.users.findById(subject.userId);
      if (!user) {
        throw new AuthError("USER_NOT_FOUND", "User not found.", 404);
      }
      email = user.email;
    }

    const customer = await config.stripe.customers.create({
      email,
      metadata: {
        [SUBJECT_KIND_KEY]: subject.kind,
        [SUBJECT_ID_KEY]: subjectId(subject),
      },
    });

    return createCustomerRecord(subject, customer.id, now);
  };

  const computeEntitlements = (
    plan: StripePlan<Feature, LimitKey>,
    status: StripeSubscriptionSnapshot["status"],
    seats?: number | null,
  ): {
    features: Partial<Record<Feature, boolean>>;
    limits: Partial<Record<LimitKey, number>>;
  } => {
    if (!ENTITLED_STATUSES.has(status)) {
      return { features: {}, limits: {} };
    }

    return {
      features: { ...(plan.features ?? {}) },
      limits: withSeatLimit({ ...(plan.limits ?? {}) }, seats, plan.seats?.enabled ? plan.seats.limitKey : undefined),
    };
  };

  const resolveSubjectFromMetadata = async (
    metadata: Record<string, string>,
    stripeCustomerId: string,
  ): Promise<StripeSubject> => {
    const kind = metadata[SUBJECT_KIND_KEY];
    const id = metadata[SUBJECT_ID_KEY];
    if (kind === "user" && id) {
      return { kind, userId: id };
    }
    if (kind === "organization" && id) {
      return { kind, organizationId: id };
    }

    const existing = await config.handlers.customers.findByStripeCustomerId(stripeCustomerId);
    if (!existing) {
      throw new AuthError("CUSTOMER_NOT_FOUND", "Stripe customer is not mapped to a billing subject.", 404);
    }
    return existing.subject;
  };

  const upsertSubscriptionSnapshot = async (
    subscription: Stripe.Subscription,
  ): Promise<StripeSubscriptionSnapshot<Feature, LimitKey>> => {
    const subscriptionRecord = subscription as Stripe.Subscription & {
      current_period_start?: number;
      current_period_end?: number;
    };
    const firstItem = subscription.items.data[0];
    if (!firstItem?.price?.id) {
      throw new AuthError("INTERNAL_ERROR", "Stripe subscription is missing a primary price item.", 500);
    }

    const metadata = toMetadataRecord(subscription.metadata);
    const { plan, billingCycle } = await resolvePlanByPriceId(firstItem.price.id, metadata[PLAN_KEY_KEY]);
    const subject = await resolveSubjectFromMetadata(metadata, String(subscription.customer));
    const existing = await config.handlers.subscriptions.findByStripeSubscriptionId(subscription.id);
    const normalizedStatus = normalizeStatus(subscription.status);
    const seats = typeof firstItem.quantity === "number" ? firstItem.quantity : null;
    const entitlements = computeEntitlements(plan, normalizedStatus, seats);

    const snapshot: StripeSubscriptionSnapshot<Feature, LimitKey> = {
      id: existing?.id ?? createId(),
      subject,
      stripeCustomerId: String(subscription.customer),
      stripeSubscriptionId: subscription.id,
      stripePriceId: firstItem.price.id,
      planKey: plan.key,
      status: normalizedStatus,
      billingCycle,
      seats,
      cancelAtPeriodEnd: subscription.cancel_at_period_end,
      currentPeriodStart: toDate(subscriptionRecord.current_period_start),
      currentPeriodEnd: toDate(subscriptionRecord.current_period_end),
      trialStartedAt: toDate(subscription.trial_start),
      trialEndsAt: toDate(subscription.trial_end),
      canceledAt: toDate(subscription.canceled_at),
      features: entitlements.features,
      limits: entitlements.limits,
      metadata,
      updatedAt: new Date(),
    };

    await config.handlers.subscriptions.upsert(snapshot);

    if (plan.trial && config.handlers.trials && (normalizedStatus === "trialing" || normalizedStatus === "active")) {
      await config.handlers.trials.markUsedTrial({
        subject,
        planKey: plan.key,
        usedAt: snapshot.updatedAt,
      });
    }

    return snapshot;
  };

  const retrieveSubscription = async (stripeSubscriptionId: string): Promise<Stripe.Subscription> => {
    return config.stripe.subscriptions.retrieve(stripeSubscriptionId);
  };

  const getManagedSubscription = async (
    subject: StripeSubject,
    subscriptionId?: string,
  ): Promise<StripeSubscriptionSnapshot<Feature, LimitKey>> => {
    const snapshot = subscriptionId
      ? await config.handlers.subscriptions.findByStripeSubscriptionId(subscriptionId)
      : await config.handlers.subscriptions.findActiveBySubject(subject);
    if (!snapshot || !subjectsEqual(snapshot.subject, subject)) {
      throw new AuthError("SUBSCRIPTION_NOT_FOUND", "Subscription not found.", 404);
    }
    return snapshot;
  };

  return {
    kind: "domain",
    method: "stripe",
    version: "2.0.0",
    createApi: (ctx) => ({
      createCheckoutSession: async (input) => {
        try {
          assertSubjectAllowed(input.subject);
          const plan = await resolvePlanByKey(input.planKey);
          assertPlanForSubject(input.subject, plan);

          const price = plan.prices[input.billingCycle];
          if (!price) {
            return errorOperation(
              new AuthError("INVALID_INPUT", `Plan '${plan.key}' does not support ${input.billingCycle} billing.`, 400),
            );
          }

          const existing = await config.handlers.subscriptions.findActiveBySubject(input.subject);
          if (existing && existing.status !== "canceled") {
            return errorOperation(new AuthError("SUBSCRIPTION_ALREADY_EXISTS", "Subscription already exists.", 409));
          }

          const quantity = resolveQuantity(input.subject, plan, input.seats);
          if (plan.trial?.oncePerSubject !== false) {
            const alreadyUsedTrial =
              plan.trial && config.handlers.trials
                ? await config.handlers.trials.hasUsedTrial({
                    subject: input.subject,
                    planKey: plan.key,
                  })
                : false;
            if (alreadyUsedTrial) {
              return errorOperation(new AuthError("TRIAL_NOT_AVAILABLE", "Trial already consumed for this plan.", 409));
            }
          }

          const customer = await ensureCustomer(ctx, input.subject, ctx.now());
          const metadata = metadataForSubject(input.subject, plan.key, input.billingCycle, {
            ...(plan.metadata ?? {}),
            ...(input.metadata ?? {}),
          });

          const session = await config.stripe.checkout.sessions.create({
            mode: "subscription",
            customer: customer.stripeCustomerId,
            success_url: input.successUrl,
            cancel_url: input.cancelUrl,
            client_reference_id: referenceForSubject(input.subject),
            locale: input.locale as Stripe.Checkout.SessionCreateParams.Locale | undefined,
            line_items: [
              {
                price: price.priceId,
                quantity,
              },
            ],
            metadata,
            subscription_data: {
              metadata,
              trial_period_days: plan.trial?.days,
            },
          });

          if (!session.url) {
            return errorOperation(
              new AuthError("INTERNAL_ERROR", "Stripe checkout session did not return a URL.", 500),
            );
          }

          return successOperation({
            url: session.url,
            checkoutSessionId: session.id,
          });
        } catch (error) {
          if (error instanceof AuthError) {
            return errorOperation(error);
          }

          return errorOperation(new AuthError("INTERNAL_ERROR", "Unable to create checkout session.", 500));
        }
      },
      createBillingPortalSession: async (input) => {
        try {
          assertSubjectAllowed(input.subject);
          const customer = await config.handlers.customers.findBySubject(input.subject);
          if (!customer) {
            return errorOperation(new AuthError("CUSTOMER_NOT_FOUND", "Billing customer not found.", 404));
          }

          const session = await config.stripe.billingPortal.sessions.create({
            customer: customer.stripeCustomerId,
            return_url: input.returnUrl,
            locale: input.locale as Stripe.BillingPortal.SessionCreateParams.Locale | undefined,
          });

          return successOperation({ url: session.url });
        } catch (error) {
          if (error instanceof AuthError) {
            return errorOperation(error);
          }

          return errorOperation(new AuthError("INTERNAL_ERROR", "Unable to create billing portal session.", 500));
        }
      },
      getSubscription: async (input) => {
        try {
          assertSubjectAllowed(input.subject);
          const subscription = await config.handlers.subscriptions.findActiveBySubject(input.subject);
          return successOperation({ subscription: subscription ?? null });
        } catch (error) {
          if (error instanceof AuthError) {
            return errorOperation(error);
          }

          return errorOperation(new AuthError("INTERNAL_ERROR", "Unable to load subscription.", 500));
        }
      },
      listSubscriptions: async (input) => {
        try {
          assertSubjectAllowed(input.subject);
          const subscriptions = await config.handlers.subscriptions.listBySubject(input.subject);
          return successOperation({ subscriptions });
        } catch (error) {
          if (error instanceof AuthError) {
            return errorOperation(error);
          }

          return errorOperation(new AuthError("INTERNAL_ERROR", "Unable to list subscriptions.", 500));
        }
      },
      cancelSubscription: async (input) => {
        try {
          assertSubjectAllowed(input.subject);
          const snapshot = await getManagedSubscription(input.subject, input.subscriptionId);
          const subscription = input.atPeriodEnd
            ? await config.stripe.subscriptions.update(snapshot.stripeSubscriptionId, {
                cancel_at_period_end: true,
              })
            : await config.stripe.subscriptions.cancel(snapshot.stripeSubscriptionId);
          const updated = await upsertSubscriptionSnapshot(subscription);
          return successOperation({ subscription: updated });
        } catch (error) {
          if (error instanceof AuthError) {
            return errorOperation(error);
          }

          return errorOperation(new AuthError("INTERNAL_ERROR", "Unable to cancel subscription.", 500));
        }
      },
      resumeSubscription: async (input) => {
        try {
          assertSubjectAllowed(input.subject);
          const snapshot = await getManagedSubscription(input.subject, input.subscriptionId);
          if (snapshot.status === "canceled") {
            return errorOperation(new AuthError("CONFLICT", "Canceled subscriptions cannot be resumed.", 409));
          }
          if (!snapshot.cancelAtPeriodEnd) {
            return errorOperation(new AuthError("CONFLICT", "Subscription is not scheduled to cancel.", 409));
          }

          const subscription = await config.stripe.subscriptions.update(snapshot.stripeSubscriptionId, {
            cancel_at_period_end: false,
          });
          const updated = await upsertSubscriptionSnapshot(subscription);
          return successOperation({ subscription: updated });
        } catch (error) {
          if (error instanceof AuthError) {
            return errorOperation(error);
          }

          return errorOperation(new AuthError("INTERNAL_ERROR", "Unable to resume subscription.", 500));
        }
      },
      changePlan: async (input) => {
        try {
          assertSubjectAllowed(input.subject);
          const targetPlan = await resolvePlanByKey(input.planKey);
          assertPlanForSubject(input.subject, targetPlan);
          const price = targetPlan.prices[input.billingCycle];
          if (!price) {
            return errorOperation(
              new AuthError(
                "INVALID_INPUT",
                `Plan '${targetPlan.key}' does not support ${input.billingCycle} billing.`,
                400,
              ),
            );
          }

          const snapshot = await getManagedSubscription(input.subject, input.subscriptionId);
          const quantity = resolveQuantity(input.subject, targetPlan, input.seats);
          const current = await retrieveSubscription(snapshot.stripeSubscriptionId);
          const item = current.items.data[0];
          if (!item?.id) {
            return errorOperation(
              new AuthError("INTERNAL_ERROR", "Stripe subscription is missing a primary item.", 500),
            );
          }

          if (input.scheduleAtPeriodEnd) {
            await (
              config.stripe.subscriptionSchedules as unknown as {
                create(params: Record<string, unknown>): Promise<unknown>;
              }
            ).create({
              from_subscription: snapshot.stripeSubscriptionId,
              end_behavior: "release",
              phases: [
                {
                  items: [
                    {
                      price: price.priceId,
                      quantity,
                    },
                  ],
                },
              ],
            });

            return successOperation({ subscription: snapshot });
          }

          const metadata = metadataForSubject(input.subject, targetPlan.key, input.billingCycle, {
            ...(targetPlan.metadata ?? {}),
            ...(snapshot.metadata ?? {}),
          });
          const updated = await config.stripe.subscriptions.update(snapshot.stripeSubscriptionId, {
            cancel_at_period_end: false,
            items: [
              {
                id: item.id,
                price: price.priceId,
                quantity,
              },
            ],
            metadata,
            proration_behavior: "create_prorations",
          });

          return successOperation({
            subscription: await upsertSubscriptionSnapshot(updated),
          });
        } catch (error) {
          if (error instanceof AuthError) {
            return errorOperation(error);
          }

          return errorOperation(new AuthError("INTERNAL_ERROR", "Unable to change plan.", 500));
        }
      },
      getEntitlements: async (input) => {
        try {
          assertSubjectAllowed(input.subject);
          const subscription = await config.handlers.subscriptions.findActiveBySubject(input.subject);
          if (!subscription) {
            return successOperation({
              features: {},
              limits: {},
            });
          }

          const entitled = ENTITLED_STATUSES.has(subscription.status);
          return successOperation({
            planKey: subscription.planKey,
            status: subscription.status,
            features: entitled ? subscription.features : {},
            limits: entitled ? subscription.limits : {},
          });
        } catch (error) {
          if (error instanceof AuthError) {
            return errorOperation(error);
          }

          return errorOperation(new AuthError("INTERNAL_ERROR", "Unable to resolve entitlements.", 500));
        }
      },
      handleWebhook: async (input) => {
        let event: Stripe.Event;
        try {
          event = config.stripe.webhooks.constructEvent(
            typeof input.rawBody === "string" ? input.rawBody : Buffer.from(input.rawBody),
            input.stripeSignature,
            config.webhookSecret,
          );
        } catch {
          return errorOperation(new AuthError("STRIPE_WEBHOOK_INVALID", "Invalid Stripe webhook signature.", 400));
        }

        const processed = await config.handlers.events.hasProcessed(event.id);
        if (processed) {
          return successOperation({
            processed: true as const,
            eventId: event.id,
          });
        }

        const processEvent = async (): Promise<OperationResult<{ processed: true; eventId: string }>> => {
          switch (event.type) {
            case "checkout.session.completed": {
              const session = event.data.object as Stripe.Checkout.Session;
              if (typeof session.customer === "string") {
                const metadata = toMetadataRecord(session.metadata);
                const subject = await resolveSubjectFromMetadata(metadata, session.customer);
                const existing = await config.handlers.customers.findByStripeCustomerId(session.customer);
                if (!existing) {
                  await createCustomerRecord(subject, session.customer, ctx.now());
                }
              }

              if (typeof session.subscription === "string") {
                await upsertSubscriptionSnapshot(await retrieveSubscription(session.subscription));
              }
              break;
            }
            case "customer.subscription.created":
            case "customer.subscription.updated":
            case "customer.subscription.deleted": {
              await upsertSubscriptionSnapshot(event.data.object as Stripe.Subscription);
              break;
            }
            case "invoice.paid":
            case "invoice.payment_failed": {
              const invoice = event.data.object as Stripe.Invoice & {
                subscription?: string | Stripe.Subscription | null;
              };
              if (typeof invoice.subscription === "string") {
                await upsertSubscriptionSnapshot(await retrieveSubscription(invoice.subscription));
              }
              break;
            }
            default:
              break;
          }

          await config.handlers.events.markProcessed({
            eventId: event.id,
            processedAt: ctx.now(),
            type: event.type,
          });

          return successOperation({
            processed: true as const,
            eventId: event.id,
          });
        };

        if (ctx.adapters.withTransaction) {
          return ctx.adapters.withTransaction(processEvent);
        }

        return processEvent();
      },
    }),
  };
};
