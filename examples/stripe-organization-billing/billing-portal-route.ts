import { NextRequest, NextResponse } from "next/server";
import { auth } from "./auth";

export async function POST(request: NextRequest): Promise<NextResponse> {
  const body = (await request.json()) as { organizationId: string };
  const stripe = auth.method("stripe");

  const result = await stripe.createBillingPortalSession({
    subject: { kind: "organization", organizationId: body.organizationId },
    returnUrl: `https://app.example.com/org/${body.organizationId}/billing`,
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
