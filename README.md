# @logi-auth/server

Server-side **"Sign in with logi"** for Node backends — confidential OAuth 2.0
Authorization Code exchange + **id_token (RS256) verification**. Zero runtime
dependencies (uses the Node global WebCrypto). Works in Next.js route handlers /
server actions, Express, Fastify, or any Node server.

This is the **confidential / backend** counterpart to the public-client SDKs
(`@logi-auth/browser`, iOS, Android, Flutter). If your RP has a backend, verify
on the server with this library — do **not** rely on a client-side check.

> **Why it matters:** a backend that skips the id_token `aud` check can be
> tricked into accepting a token minted for a *different* client (cross-client
> account takeover). `exchangeCodeAndVerify()` always verifies
> signature + iss + aud + exp + nonce before returning `sub`.

## Supported versions

| Requirement | Version |
|-------------|---------|
| **Node.js** | **>= 20** (global `fetch` + `crypto.subtle`; on Node 18 pass your own `fetch`) |
| **Next.js** | **>= 13.4** (App Router — route handlers / server actions); Pages API routes also fine |
| Express / Fastify | any current version |
| TypeScript | >= 5.0 (types shipped; JS consumers fine too) |

## Install

```bash
npm i @logi-auth/server
```

## Next.js (App Router) example

```ts
// app/api/auth/logi/route.ts  (start the flow)
import { LogiAuthServer } from "@logi-auth/server";
import { cookies } from "next/headers";
import { randomBytes } from "node:crypto";

const logi = new LogiAuthServer({
  clientId: process.env.LOGI_CLIENT_ID!,
  clientSecret: process.env.LOGI_CLIENT_SECRET!, // confidential client
  redirectUri: "https://app.example.com/api/auth/logi/callback",
});

export async function GET() {
  const state = randomBytes(16).toString("hex");
  const nonce = randomBytes(16).toString("hex");
  const jar = await cookies();
  jar.set("logi_state", state, { httpOnly: true, secure: true, sameSite: "lax" });
  jar.set("logi_nonce", nonce, { httpOnly: true, secure: true, sameSite: "lax" });
  return Response.redirect(logi.authorizationUrl({ state, nonce }));
}
```

```ts
// app/api/auth/logi/callback/route.ts  (finish + verify)
export async function GET(req: Request) {
  const url = new URL(req.url);
  const jar = await cookies();
  if (url.searchParams.get("state") !== jar.get("logi_state")?.value) {
    return new Response("state mismatch", { status: 400 });
  }
  const session = await logi.exchangeCodeAndVerify({
    code: url.searchParams.get("code")!,
    nonce: jar.get("logi_nonce")!.value,
  });
  // session.sub is the verified pairwise subject — key your user record on it.
  // ...set your own session cookie here...
  return Response.redirect("https://app.example.com/");
}
```

## Public client (PKCE, no secret)

Omit `clientSecret` and pass a `codeChallenge` / `codeVerifier`:

```ts
const logi = new LogiAuthServer({ clientId, redirectUri }); // no secret
const url = logi.authorizationUrl({ state, nonce, codeChallenge });
const session = await logi.exchangeCodeAndVerify({ code, nonce, codeVerifier });
```

## License

MIT
