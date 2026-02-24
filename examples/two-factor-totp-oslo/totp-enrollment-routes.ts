import { NextRequest, NextResponse } from "next/server";
import { auth } from "./auth";

export async function beginTotpEnrollment(request: NextRequest): Promise<NextResponse> {
  const body = (await request.json()) as { userId: string };
  const twoFactor = auth.method("two_factor");
  const result = await twoFactor.beginTotpEnrollment(body.userId);

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
    enrollmentId: result.data.enrollmentId,
    otpauthUri: result.data.otpauthUri,
  });
}

export async function confirmTotpEnrollment(request: NextRequest): Promise<NextResponse> {
  const body = (await request.json()) as { enrollmentId: string; code: string };
  const twoFactor = auth.method("two_factor");
  const result = await twoFactor.confirmTotpEnrollment({
    enrollmentId: body.enrollmentId,
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

  return NextResponse.json({ ok: true, enabled: result.data.enabled });
}
