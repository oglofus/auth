import { NextRequest, NextResponse } from "next/server";
import { auth } from "./auth";

export async function GET(request: NextRequest): Promise<NextResponse> {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const expectedState = request.cookies.get("oauth_state")?.value;
  const codeVerifier = request.cookies.get("oauth_code_verifier")?.value;

  if (!code || !state || !expectedState || state !== expectedState || !codeVerifier) {
    return NextResponse.json({ ok: false, code: "OAUTH_INVALID_CALLBACK" }, { status: 400 });
  }

  const result = await auth.authenticate({
    method: "oauth2",
    provider: "google",
    authorizationCode: code,
    redirectUri: process.env.GOOGLE_REDIRECT_URI!,
    codeVerifier,
    idempotencyKey: state,
  });

  if (!result.ok) {
    if (result.error.code === "PROFILE_COMPLETION_REQUIRED") {
      return NextResponse.json(
        {
          ok: false,
          code: result.error.code,
          pendingProfileId: result.error.meta?.pendingProfileId,
          missingFields: result.error.meta?.missingFields,
        },
        { status: 400 },
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

  return NextResponse.json({
    ok: true,
    sessionId: result.sessionId,
    user: result.user,
  });
}
