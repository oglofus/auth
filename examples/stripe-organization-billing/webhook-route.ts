import { NextRequest, NextResponse } from "next/server";
import { auth } from "./auth";

export async function POST(request: NextRequest): Promise<NextResponse> {
  const signature = request.headers.get("stripe-signature");
  if (!signature) {
    return NextResponse.json({ ok: false, code: "MISSING_STRIPE_SIGNATURE" }, { status: 400 });
  }

  const rawBody = await request.text();
  const stripe = auth.method("stripe");
  const result = await stripe.handleWebhook({
    rawBody,
    stripeSignature: signature,
  });

  if (!result.ok) {
    return NextResponse.json(
      { ok: false, code: result.error.code, message: result.error.message, issues: result.issues },
      { status: result.error.status },
    );
  }

  return NextResponse.json({
    ok: true,
    eventId: result.data.eventId,
    processed: result.data.processed,
  });
}
