import { NextResponse } from "next/server";
import { createGoogleAuthorization } from "./auth";

export async function GET(): Promise<NextResponse> {
  const { state, codeVerifier, url } = createGoogleAuthorization();

  const response = NextResponse.redirect(url);
  response.cookies.set("oauth_state", state, { httpOnly: true, sameSite: "lax", path: "/" });
  response.cookies.set("oauth_code_verifier", codeVerifier, {
    httpOnly: true,
    sameSite: "lax",
    path: "/",
  });
  return response;
}
