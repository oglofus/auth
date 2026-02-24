import { NextRequest, NextResponse } from "next/server";
import { auth } from "./auth";

export async function POST(request: NextRequest): Promise<NextResponse> {
  const body = (await request.json()) as { pendingAuthId: string; code: string };
  const result = await auth.verifySecondFactor({
    method: "totp",
    pendingAuthId: body.pendingAuthId,
    code: body.code,
  });

  if (!result.ok) {
    return NextResponse.json(
      {
        ok: false,
        code: result.error.code,
        message: result.error.message,
        issues: result.issues,
      },
      { status: result.error.status },
    );
  }

  return NextResponse.json({
    ok: true,
    sessionId: result.sessionId,
    user: result.user,
  });
}
