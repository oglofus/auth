import { NextRequest, NextResponse } from "next/server";
import { auth } from "./auth";

export async function POST(request: NextRequest): Promise<NextResponse> {
  const body = (await request.json()) as {
    organizationId: string;
    seats: number;
    billingCycle: "monthly" | "annual";
  };

  const stripe = auth.method("stripe");
  const result = await stripe.createCheckoutSession({
    subject: { kind: "organization", organizationId: body.organizationId },
    planKey: "team",
    billingCycle: body.billingCycle,
    seats: body.seats,
    successUrl: `https://app.example.com/org/${body.organizationId}/billing/success`,
    cancelUrl: `https://app.example.com/org/${body.organizationId}/billing`,
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
