import {
  calculateJwkThumbprint,
  exportJWK,
  generateKeyPair,
  SignJWT,
  type JWK,
} from "jose";
import { TOKEN_AUDIENCE, TOKEN_ISSUER, type Principal } from "@zt/common";

export type TokenIssuer = {
  readonly issue: (principal: Principal) => Promise<string>;
  readonly jwks: { readonly keys: readonly JWK[] };
};

export const TOKEN_LIFETIME_SECONDS = 300;

// The signing key lives only in memory, so there is no private key to store or leak.
// A restart rotates the key, which at worst invalidates five-minute tokens.
export const createTokenIssuer = async (): Promise<TokenIssuer> => {
  const { publicKey, privateKey } = await generateKeyPair("ES256");
  const publicJwk = await exportJWK(publicKey);
  const kid = await calculateJwkThumbprint(publicJwk);
  return {
    issue: (principal) =>
      new SignJWT({ role: principal.role })
        .setProtectedHeader({ alg: "ES256", kid })
        .setSubject(principal.id)
        .setIssuer(TOKEN_ISSUER)
        .setAudience(TOKEN_AUDIENCE)
        .setIssuedAt()
        .setExpirationTime(`${TOKEN_LIFETIME_SECONDS}s`)
        .sign(privateKey),
    jwks: { keys: [{ ...publicJwk, kid, alg: "ES256", use: "sig" }] },
  };
};
