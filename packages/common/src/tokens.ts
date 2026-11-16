import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from "jose";
import { z } from "zod";
import {
  ROLES,
  TOKEN_AUDIENCE,
  TOKEN_ISSUER,
  type Principal,
} from "./principal";

export type TokenVerifier = (token: string) => Promise<Principal>;

export const createRemoteTokenVerifier = (jwksUrl: string): TokenVerifier =>
  createTokenVerifier(createRemoteJWKSet(new URL(jwksUrl)));

export const createTokenVerifier =
  (keys: JWTVerifyGetKey): TokenVerifier =>
  async (token) => {
    const { payload } = await jwtVerify(token, keys, {
      issuer: TOKEN_ISSUER,
      audience: TOKEN_AUDIENCE,
      algorithms: ["ES256"],
    });
    const claims = claimsSchema.parse(payload);
    return { id: claims.sub, role: claims.role };
  };

const claimsSchema = z.object({
  sub: z.string().min(1),
  role: z.enum(ROLES),
});
