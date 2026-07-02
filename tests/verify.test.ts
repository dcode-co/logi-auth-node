import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { verifyIdToken } from "../src/verify.js";

// 4-SDK shared golden vectors (SoT: ../../test-vectors/generate.mjs). The Node
// server verifier reuses the same verify.ts as the browser SDK (WebCrypto is
// global in Node 20+), so it MUST pass the identical vectors.
interface GoldenCase {
  name: string;
  token: string;
  // Present-only at_hash binding: threaded into verifyIdToken when set (cases
  // without it skip at_hash, staying backward compatible).
  accessToken?: string;
  expect: { valid: true; sub: string } | { valid: false; error: string };
}
interface GoldenVectors {
  now: number;
  expected: { issuer: string; clientId: string; nonce?: string };
  jwks: { keys: Array<{ kty: string; n: string; e: string; kid: string; alg?: string; use?: string }> };
  cases: GoldenCase[];
}

const vectors = JSON.parse(
  readFileSync(new URL("./fixtures/id-token-vectors.json", import.meta.url), "utf8")
) as GoldenVectors;

describe("id_token golden vectors (Node server)", () => {
  const opts = {
    jwks: vectors.jwks,
    expected: vectors.expected,
    now: vectors.now,
    clockSkewSec: 60,
  };

  for (const c of vectors.cases) {
    it(c.name, async () => {
      const caseOpts = { ...opts, accessToken: c.accessToken };
      if (c.expect.valid) {
        const result = await verifyIdToken(c.token, caseOpts);
        expect(result.sub).toBe(c.expect.sub);
      } else {
        await expect(verifyIdToken(c.token, caseOpts)).rejects.toMatchObject({
          code: c.expect.error,
        });
      }
    });
  }

  it("covers the full set (>= 9 cases incl. valid)", () => {
    expect(vectors.cases.length).toBeGreaterThanOrEqual(9);
    expect(vectors.cases.some((c) => c.name === "valid")).toBe(true);
  });
});
