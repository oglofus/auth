import { json, type RequestHandler } from "@sveltejs/kit";
import { auth } from "./auth";

export const POST: RequestHandler = async ({ request }) => {
  const body = (await request.json()) as { email: string; locale?: string };
  const otpApi = auth.method("email_otp");
  const result = await otpApi.request({ email: body.email, locale: body.locale });

  if (!result.ok) {
    return json(
      {
        ok: false,
        code: result.error.code,
        message: result.error.message,
        issues: result.issues,
      },
      { status: result.error.status },
    );
  }

  return json({
    ok: true,
    challengeId: result.data.challengeId,
    disposition: result.data.disposition,
  });
};
