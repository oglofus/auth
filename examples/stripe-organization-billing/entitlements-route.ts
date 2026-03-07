import { NextRequest, NextResponse } from "next/server";
import { auth } from "./auth";

export async function GET(request: NextRequest): Promise<NextResponse> {
  const organizationId = request.nextUrl.searchParams.get("organizationId");
  const userId = request.nextUrl.searchParams.get("userId");

  if (!organizationId || !userId) {
    return NextResponse.json({ ok: false, code: "MISSING_ORGANIZATION_OR_USER_ID" }, { status: 400 });
  }

  const organizations = auth.method("organizations");
  const result = await organizations.getEntitlements({ organizationId, userId });

  if (!result.ok) {
    return NextResponse.json(
      { ok: false, code: result.error.code, message: result.error.message, issues: result.issues },
      { status: result.error.status },
    );
  }

  return NextResponse.json({
    ok: true,
    entitlements: result.data,
  });
}
