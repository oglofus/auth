import { NextRequest, NextResponse } from "next/server";
import { auth } from "./auth";

export async function POST(request: NextRequest): Promise<NextResponse> {
  const body = (await request.json()) as { email: string; password: string };
  const result = await auth.authenticate({
    method: "password",
    email: body.email,
    password: body.password,
  });

  if (result.ok) {
    return NextResponse.json({
      ok: true,
      sessionId: result.sessionId,
      user: result.user,
    });
  }

  if (result.error.code === "TWO_FACTOR_REQUIRED") {
    return NextResponse.json(
      {
        ok: false,
        code: result.error.code,
        pendingAuthId: result.error.meta?.pendingAuthId,
        availableSecondFactors: result.error.meta?.availableSecondFactors,
      },
      { status: 401 },
    );
  }

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
