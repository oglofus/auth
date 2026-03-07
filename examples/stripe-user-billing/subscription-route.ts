import { NextRequest, NextResponse } from "next/server";
import { auth } from "./auth";

export async function GET(request: NextRequest): Promise<NextResponse> {
  const userId = request.nextUrl.searchParams.get("userId");
  if (!userId) {
    return NextResponse.json({ ok: false, code: "MISSING_USER_ID" }, { status: 400 });
  }

  const stripe = auth.method("stripe");
  const [subscription, entitlements] = await Promise.all([
    stripe.getSubscription({
      subject: { kind: "user", userId },
    }),
    stripe.getEntitlements({
      subject: { kind: "user", userId },
    }),
  ]);

  if (!subscription.ok) {
    return NextResponse.json(
      {
        ok: false,
        code: subscription.error.code,
        message: subscription.error.message,
        issues: subscription.issues,
      },
      { status: subscription.error.status },
    );
  }

  if (!entitlements.ok) {
    return NextResponse.json(
      {
        ok: false,
        code: entitlements.error.code,
        message: entitlements.error.message,
        issues: entitlements.issues,
      },
      { status: entitlements.error.status },
    );
  }

  return NextResponse.json({
    ok: true,
    subscription: subscription.data.subscription,
    entitlements: entitlements.data,
  });
}
