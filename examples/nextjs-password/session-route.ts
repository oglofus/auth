import { NextRequest, NextResponse } from "next/server";
import { auth } from "./auth";

export async function GET(request: NextRequest): Promise<NextResponse> {
  const sessionId = request.headers.get("x-session-id");
  if (!sessionId) {
    return NextResponse.json({ ok: false, code: "MISSING_SESSION_ID" }, { status: 400 });
  }

  const session = await auth.validateSession(sessionId);
  if (!session.ok) {
    return NextResponse.json({ ok: false }, { status: 401 });
  }

  return NextResponse.json({ ok: true, userId: session.userId });
}

export async function DELETE(request: NextRequest): Promise<NextResponse> {
  const sessionId = request.headers.get("x-session-id");
  if (!sessionId) {
    return NextResponse.json({ ok: false, code: "MISSING_SESSION_ID" }, { status: 400 });
  }

  await auth.signOut(sessionId);
  return NextResponse.json({ ok: true });
}
