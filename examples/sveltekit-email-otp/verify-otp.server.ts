import { json, type RequestHandler } from "@sveltejs/kit";
import { auth } from "./auth";

export const POST: RequestHandler = async ({ request }) => {
  const body = (await request.json()) as {
    challengeId: string;
    code: string;
    given_name?: string;
  };

  const login = await auth.authenticate({
    method: "email_otp",
    challengeId: body.challengeId,
    code: body.code,
  });

  if (login.ok) {
    return json({ ok: true, mode: "login", sessionId: login.sessionId, user: login.user });
  }

  if (login.error.code !== "ACCOUNT_NOT_FOUND") {
    return json(
      {
        ok: false,
        code: login.error.code,
        message: login.error.message,
        issues: login.issues,
      },
      { status: login.error.status },
    );
  }

  const register = await auth.register({
    method: "email_otp",
    challengeId: body.challengeId,
    code: body.code,
    given_name: body.given_name ?? "",
  });

  if (!register.ok) {
    return json(
      {
        ok: false,
        code: register.error.code,
        message: register.error.message,
        issues: register.issues,
      },
      { status: register.error.status },
    );
  }

  return json({
    ok: true,
    mode: "register",
    sessionId: register.sessionId,
    user: register.user,
  });
};
