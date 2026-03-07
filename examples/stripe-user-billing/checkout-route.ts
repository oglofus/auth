import { NextRequest, NextResponse } from "next/server";
import { auth } from "./auth";

export async function POST(request: NextRequest): Promise<NextResponse> {
  const body = (await request.json()) as {
    userId: string;
    planKey: string;
    billingCycle: "monthly" | "annual";
  };

  const stripe = auth.method("stripe");
  const result = await stripe.createCheckoutSession({
    subject: { kind: "user", userId: body.userId },
    planKey: body.planKey,
    billingCycle: body.billingCycle,
    successUrl: "https://app.example.com/billing/success",
    cancelUrl: "https://app.example.com/billing/cancel",
  });

  if (!result.ok) {
    return NextResponse.json(
      { ok: false, code: result.error.code, message: result.error.message, issues: result.issues },
      { status: result.error.status },
    );
  }

  return NextResponse.json({
    ok: true,
    checkoutSessionId: result.data.checkoutSessionId,
    url: result.data.url,
  });
}
