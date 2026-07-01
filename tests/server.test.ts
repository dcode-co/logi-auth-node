import { describe, it, expect } from "vitest";
import { LogiAuthServer, LogiAuthServerError } from "../src/server.js";

const base = {
  clientId: "logi_test_client_abc",
  clientSecret: "secret_xyz",
  redirectUri: "https://rp.example.com/auth/callback",
  issuer: "https://api.1pass.dev",
};

function jsonResponse(status: number, body: string): Response {
  return new Response(body, { status, headers: { "content-type": "application/json" } });
}

describe("LogiAuthServer.authorizationUrl", () => {
  it("builds the authorize URL with state, nonce, and PKCE", () => {
    const server = new LogiAuthServer({ ...base, fetch: (async () => new Response()) as typeof fetch });
    const url = new URL(
      server.authorizationUrl({ state: "st", nonce: "no", codeChallenge: "cc" })
    );
    expect(url.pathname).toBe("/oauth/authorize");
    expect(url.searchParams.get("client_id")).toBe(base.clientId);
    expect(url.searchParams.get("redirect_uri")).toBe(base.redirectUri);
    expect(url.searchParams.get("state")).toBe("st");
    expect(url.searchParams.get("nonce")).toBe("no");
    expect(url.searchParams.get("code_challenge")).toBe("cc");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("scope")).toBe("openid profile:basic email");
  });
});

describe("LogiAuthServer.exchangeCodeAndVerify error handling", () => {
  it("throws token_exchange_failed on a non-2xx token response", async () => {
    const server = new LogiAuthServer({
      ...base,
      fetch: (async () => jsonResponse(401, '{"error":"invalid_client"}')) as typeof fetch,
    });
    await expect(
      server.exchangeCodeAndVerify({ code: "c", nonce: "n" })
    ).rejects.toMatchObject({ code: "token_exchange_failed" });
  });

  it("throws token_exchange_failed on a malformed 2xx body (proxy error page)", async () => {
    const server = new LogiAuthServer({
      ...base,
      fetch: (async () => new Response("<html>proxy error</html>", { status: 200 })) as typeof fetch,
    });
    await expect(
      server.exchangeCodeAndVerify({ code: "c", nonce: "n" })
    ).rejects.toMatchObject({ code: "token_exchange_failed" });
  });

  it("throws missing_id_token when the token response has no id_token", async () => {
    const server = new LogiAuthServer({
      ...base,
      fetch: (async () => jsonResponse(200, '{"access_token":"at","token_type":"Bearer"}')) as typeof fetch,
    });
    await expect(
      server.exchangeCodeAndVerify({ code: "c", nonce: "n" })
    ).rejects.toMatchObject({ code: "missing_id_token" });
  });

  it("surfaces failures as the typed LogiAuthServerError", async () => {
    const server = new LogiAuthServer({
      ...base,
      fetch: (async () => jsonResponse(500, "boom")) as typeof fetch,
    });
    const err = await server.exchangeCodeAndVerify({ code: "c", nonce: "n" }).catch((e) => e);
    expect(err).toBeInstanceOf(LogiAuthServerError);
  });
});
