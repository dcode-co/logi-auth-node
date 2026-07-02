import { describe, it, expect } from "vitest";
import {
  createHash,
  createSign,
  createPublicKey,
  generateKeyPairSync,
} from "node:crypto";
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

// --- RS256 signing helpers for the at_hash wiring test ---
const { privateKey: SIGN_KEY } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const SIGN_PEM = SIGN_KEY.export({ type: "pkcs8", format: "pem" }) as string;
const SIGN_JWK = createPublicKey(SIGN_PEM).export({ format: "jwk" }) as { n: string; e: string };
const SIGN_KID = "server-test-kid";
const SIGN_JWKS = {
  keys: [{ kty: "RSA", n: SIGN_JWK.n, e: SIGN_JWK.e, kid: SIGN_KID, alg: "RS256", use: "sig" }],
};
const b64url = (x: string) => Buffer.from(x).toString("base64url");
function signIdToken(payload: Record<string, unknown>): string {
  const header = { alg: "RS256", kid: SIGN_KID, typ: "JWT" };
  const input = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  return `${input}.${createSign("RSA-SHA256").update(input).sign(SIGN_PEM).toString("base64url")}`;
}
function atHashFor(accessToken: string): string {
  return createHash("sha256")
    .update(Buffer.from(accessToken, "utf8"))
    .digest()
    .subarray(0, 16)
    .toString("base64url");
}
function routingFetch(tokenBody: string): typeof fetch {
  return (async (url: string) => {
    if (String(url).includes("/oauth/token")) return jsonResponse(200, tokenBody);
    if (String(url).includes("/.well-known/jwks.json")) return jsonResponse(200, JSON.stringify(SIGN_JWKS));
    throw new Error("unexpected fetch: " + url);
  }) as typeof fetch;
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

  it("rejects a missing nonce before any network call (invalid_nonce)", async () => {
    let called = false;
    const server = new LogiAuthServer({
      ...base,
      fetch: (async () => {
        called = true;
        return new Response("{}", { status: 200 });
      }) as typeof fetch,
    });
    await expect(
      server.exchangeCodeAndVerify({ code: "c", nonce: "" })
    ).rejects.toMatchObject({ code: "invalid_nonce" });
    expect(called).toBe(false);
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

describe("LogiAuthServer at_hash binding (wiring)", () => {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: base.issuer,
    aud: base.clientId,
    sub: "u_srv_1",
    exp: now + 3600,
    iat: now - 10,
    nonce: "n_srv",
    jti: "j_srv",
  };

  it("rejects (before returning a session) when at_hash does not bind the access_token", async () => {
    const idToken = signIdToken({ ...payload, at_hash: atHashFor("the-real-access-token") });
    const server = new LogiAuthServer({
      ...base,
      fetch: routingFetch(
        JSON.stringify({ access_token: "a-SWAPPED-access-token", id_token: idToken, token_type: "Bearer" })
      ),
    });
    await expect(
      server.exchangeCodeAndVerify({ code: "c", nonce: "n_srv" })
    ).rejects.toMatchObject({ code: "id_token_invalid" });
  });

  it("returns a verified session when at_hash binds the access_token", async () => {
    const accessToken = "matching-access-token";
    const idToken = signIdToken({ ...payload, at_hash: atHashFor(accessToken) });
    const server = new LogiAuthServer({
      ...base,
      fetch: routingFetch(
        JSON.stringify({ access_token: accessToken, id_token: idToken, token_type: "Bearer" })
      ),
    });
    const session = await server.exchangeCodeAndVerify({ code: "c", nonce: "n_srv" });
    expect(session.sub).toBe("u_srv_1");
    expect(session.accessToken).toBe(accessToken);
  });
});
