// Server-side "Sign in with logi" for Node backends (Next.js route handlers /
// server actions, Express, Fastify, …). Confidential-client OAuth 2.0 code
// exchange + **id_token verification** (RS256, via the shared verify.ts).
//
// Why this exists: a backend RP that skips the id_token `aud` check can be
// tricked into accepting a token minted for a DIFFERENT client (cross-client
// account takeover — the launchcrew/krx incident). exchangeCodeAndVerify()
// ALWAYS verifies signature + iss + aud + exp + nonce before returning `sub`,
// so that class of bug cannot happen if you use this helper.

import {
  verifyIdToken,
  IdTokenError,
  type Jwks,
} from "./verify.js";

export interface LogiAuthServerOptions {
  /** client_id issued when the app was registered. */
  clientId: string;
  /** redirect_uri registered server-side (your callback route). */
  redirectUri: string;
  /**
   * client_secret for a confidential client. Omit for a public client that
   * proves the exchange with PKCE (pass `codeVerifier` to exchange…()).
   */
  clientSecret?: string;
  /** logi IdP base URL. Default: https://api.1pass.dev */
  issuer?: string;
  /** Expected `iss` claim (the string "logi", not the URL). Default: "logi". */
  tokenIssuer?: string;
  /** Default scopes. Default: ["openid", "profile:basic", "email"]. */
  scopes?: string[];
  /** Injectable fetch (tests / custom agents). Default: global fetch. */
  fetch?: typeof fetch;
  /** JWKS cache TTL in ms. Default: 3_600_000 (1h). */
  jwksCacheTtlMs?: number;
}

export interface AuthorizationUrlParams {
  /** CSRF token you persist in the session and re-check on callback. */
  state: string;
  /** OIDC nonce you persist in the session and pass to exchange…(). */
  nonce: string;
  scopes?: string[];
  /** PKCE S256 code_challenge (recommended even for confidential clients). */
  codeChallenge?: string;
  prompt?: string;
}

export interface ExchangeParams {
  code: string;
  /** The nonce from the matching authorizationUrl() call — always verified. */
  nonce: string;
  /** PKCE code_verifier, if you used a code_challenge. */
  codeVerifier?: string;
}

export interface LogiServerSession {
  /** Verified subject — pairwise per client. Safe to key your user record on. */
  sub: string;
  email?: string;
  idToken: string;
  accessToken: string;
  refreshToken?: string;
  /** Unix ms when the access token expires, if the server returned expires_in. */
  expiresAt?: number;
  scope?: string;
  claims: Record<string, unknown>;
}

export type LogiAuthServerErrorCode =
  | "invalid_nonce"
  | "token_exchange_failed"
  | "missing_id_token"
  | "id_token_invalid"
  | "jwks_fetch_failed"
  | "network_error";

export class LogiAuthServerError extends Error {
  constructor(
    public readonly code: LogiAuthServerErrorCode,
    message: string,
    public readonly detail?: unknown
  ) {
    super(message);
    this.name = "LogiAuthServerError";
  }
}

export class LogiAuthServer {
  readonly clientId: string;
  readonly redirectUri: string;
  readonly issuer: string;
  readonly tokenIssuer: string;
  readonly defaultScopes: string[];
  private readonly clientSecret?: string;
  private readonly fetchImpl: typeof fetch;
  private readonly jwksCacheTtlMs: number;
  private jwksCache?: { jwks: Jwks; fetchedAt: number };

  constructor(opts: LogiAuthServerOptions) {
    if (!opts.clientId) throw new Error("LogiAuthServer: clientId is required");
    if (!opts.redirectUri) throw new Error("LogiAuthServer: redirectUri is required");
    this.clientId = opts.clientId;
    this.redirectUri = opts.redirectUri;
    this.clientSecret = opts.clientSecret;
    this.issuer = (opts.issuer ?? "https://api.1pass.dev").replace(/\/+$/, "");
    this.tokenIssuer = opts.tokenIssuer ?? "logi";
    this.defaultScopes = opts.scopes ?? ["openid", "profile:basic", "email"];
    this.fetchImpl = opts.fetch ?? globalThis.fetch;
    this.jwksCacheTtlMs = opts.jwksCacheTtlMs ?? 3_600_000;
    if (!this.fetchImpl) {
      throw new Error(
        "LogiAuthServer: global fetch is unavailable (Node < 18). Pass opts.fetch."
      );
    }
  }

  /** Build the /oauth/authorize URL to redirect the browser to. */
  authorizationUrl(params: AuthorizationUrlParams): string {
    const url = new URL(`${this.issuer}/oauth/authorize`);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", this.clientId);
    url.searchParams.set("redirect_uri", this.redirectUri);
    url.searchParams.set("scope", (params.scopes ?? this.defaultScopes).join(" "));
    url.searchParams.set("state", params.state);
    url.searchParams.set("nonce", params.nonce);
    if (params.codeChallenge) {
      url.searchParams.set("code_challenge", params.codeChallenge);
      url.searchParams.set("code_challenge_method", "S256");
    }
    if (params.prompt) url.searchParams.set("prompt", params.prompt);
    return url.toString();
  }

  /**
   * Exchange the authorization code and verify the id_token. Returns a verified
   * session — `sub` is set only after signature + iss + aud + exp + nonce all
   * pass. Throws LogiAuthServerError on any failure.
   */
  async exchangeCodeAndVerify(params: ExchangeParams): Promise<LogiServerSession> {
    // The server flow always issued a nonce in authorizationUrl(), so a missing
    // nonce here (e.g. an expired session) is a bug — never proceed with the
    // nonce check silently disabled. (codex P1.)
    if (!params.nonce) {
      throw new LogiAuthServerError(
        "invalid_nonce",
        "nonce is required — the sign-in session may have expired"
      );
    }

    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code: params.code,
      redirect_uri: this.redirectUri,
      client_id: this.clientId,
    });
    if (this.clientSecret) body.set("client_secret", this.clientSecret);
    if (params.codeVerifier) body.set("code_verifier", params.codeVerifier);

    let resp: Response;
    try {
      resp = await this.fetchImpl(`${this.issuer}/oauth/token`, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Accept: "application/json",
        },
        body: body.toString(),
      });
    } catch (cause) {
      throw new LogiAuthServerError("network_error", "Token exchange network error", cause);
    }

    const raw = await resp.text();
    if (!resp.ok) {
      const trimmed = raw.length > 2048 ? raw.slice(0, 2048) + "…[truncated]" : raw;
      throw new LogiAuthServerError(
        "token_exchange_failed",
        `Token exchange failed: HTTP ${resp.status}`,
        { status: resp.status, body: trimmed }
      );
    }

    // A 2xx body can still be malformed (proxy error page). Don't leak a raw
    // SyntaxError past the typed-error contract.
    let tokens: Record<string, unknown>;
    try {
      tokens = JSON.parse(raw);
    } catch (cause) {
      throw new LogiAuthServerError("token_exchange_failed", "Token response was not valid JSON", cause);
    }
    if (typeof tokens.access_token !== "string") {
      throw new LogiAuthServerError("token_exchange_failed", "Token response was missing access_token");
    }

    const idToken = tokens.id_token;
    if (typeof idToken !== "string" || !idToken) {
      throw new LogiAuthServerError(
        "missing_id_token",
        "Token response had no id_token — was `openid` in the scopes?"
      );
    }

    const verified = await this.verifyWithRotationRetry(idToken, params.nonce);

    const email = verified.claims["email"];
    const expiresIn = tokens.expires_in;
    return {
      sub: verified.sub,
      email: typeof email === "string" ? email : undefined,
      idToken,
      accessToken: tokens.access_token,
      refreshToken: typeof tokens.refresh_token === "string" ? tokens.refresh_token : undefined,
      expiresAt: typeof expiresIn === "number" ? Date.now() + expiresIn * 1000 : undefined,
      scope: typeof tokens.scope === "string" ? tokens.scope : undefined,
      claims: verified.claims,
    };
  }

  private async verifyWithRotationRetry(idToken: string, nonce: string) {
    const expected = { issuer: this.tokenIssuer, clientId: this.clientId, nonce };
    const [jwks, fromCache] = await this.fetchJwks(false);
    try {
      return await verifyIdToken(idToken, { jwks, expected });
    } catch (cause) {
      if (cause instanceof IdTokenError && cause.code === "unknown_kid" && fromCache) {
        // Key rotation within the cache TTL — bust + refetch once.
        const [fresh] = await this.fetchJwks(true);
        try {
          return await verifyIdToken(idToken, { jwks: fresh, expected });
        } catch (retry) {
          throw asIdTokenInvalid(retry);
        }
      }
      throw asIdTokenInvalid(cause);
    }
  }

  private async fetchJwks(forceRefresh: boolean): Promise<[Jwks, boolean]> {
    const cached = this.jwksCache;
    if (!forceRefresh && cached && Date.now() - cached.fetchedAt < this.jwksCacheTtlMs) {
      return [cached.jwks, true];
    }
    let resp: Response;
    try {
      resp = await this.fetchImpl(`${this.issuer}/.well-known/jwks.json`, {
        headers: { Accept: "application/json" },
      });
    } catch (cause) {
      throw new LogiAuthServerError("network_error", "JWKS fetch network error", cause);
    }
    if (!resp.ok) {
      throw new LogiAuthServerError("jwks_fetch_failed", `JWKS fetch failed: HTTP ${resp.status}`);
    }
    let jwks: Jwks;
    try {
      jwks = (await resp.json()) as Jwks;
      if (!jwks || !Array.isArray(jwks.keys)) throw new Error("missing keys[]");
    } catch (cause) {
      throw new LogiAuthServerError("jwks_fetch_failed", "JWKS response was malformed", cause);
    }
    this.jwksCache = { jwks, fetchedAt: Date.now() };
    return [jwks, false];
  }
}

function asIdTokenInvalid(cause: unknown): LogiAuthServerError {
  const code = cause instanceof IdTokenError ? cause.code : "unknown";
  return new LogiAuthServerError("id_token_invalid", `id_token verification failed (${code}).`, cause);
}
