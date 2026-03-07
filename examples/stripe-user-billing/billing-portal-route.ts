import { NextRequest, NextResponse } from "next/server";
import { auth } from "./auth";

export async function POST(request: NextRequest): Promise<NextResponse> {
  const body = (await request.json()) as { userId: string };
  const stripe = auth.method("stripe");

  const result = await stripe.createBillingPortalSession({
    subject: { kind: "user", userId: body.userId },
    returnUrl: "https://app.example.com/settings/billing",
  });

  if (!result.ok) {
    return NextResponse.json(
      { ok: false, code: result.error.code, message: result.error.message, issues: result.issues },
      { status: result.error.status },
    );
  }

  return NextResponse.json({
    ok: true,
    url: result.data.url,
  });
}
