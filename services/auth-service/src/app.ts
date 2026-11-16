import express, { type Express } from "express";
import { z } from "zod";
import { errorHandler, HttpError } from "@zt/common";
import { login, register, type AccountDeps } from "./accounts";
import { authenticateService, type ServiceClients } from "./serviceClients";
import { TOKEN_LIFETIME_SECONDS, type TokenIssuer } from "./tokenIssuer";

export type AuthAppDeps = AccountDeps & {
  readonly tokens: TokenIssuer;
  readonly serviceClients: ServiceClients;
};

export const createApp = (deps: AuthAppDeps): Express => {
  const app = express();
  app.disable("x-powered-by");
  app.use(express.json({ limit: "10kb" }));

  app.get("/health", (_req, res) => {
    res.json({ status: "ok" });
  });

  app.get("/.well-known/jwks.json", (_req, res) => {
    res.json(deps.tokens.jwks);
  });

  app.post("/register", async (req, res) => {
    const { email, password } = credentialsSchema.parse(req.body);
    const enrollment = await register(deps, email, password);
    if (!enrollment) {
      throw new HttpError(409, "Email already registered.");
    }
    res.status(201).json(enrollment);
  });

  app.post("/login", async (req, res) => {
    const { email, password, totpCode } = loginSchema.parse(req.body);
    const principal = await login(deps, email, password, totpCode);
    if (!principal) {
      throw new HttpError(401, "Invalid credentials.");
    }
    res.json(await tokenResponse(deps.tokens, principal));
  });

  app.post("/service-token", async (req, res) => {
    const { clientId, clientSecret } = serviceSchema.parse(req.body);
    const principal = authenticateService(
      deps.serviceClients,
      clientId,
      clientSecret,
    );
    if (!principal) {
      throw new HttpError(401, "Invalid credentials.");
    }
    res.json(await tokenResponse(deps.tokens, principal));
  });

  app.use(errorHandler);
  return app;
};

const tokenResponse = async (
  tokens: TokenIssuer,
  principal: Parameters<TokenIssuer["issue"]>[0],
) => ({
  accessToken: await tokens.issue(principal),
  tokenType: "Bearer",
  expiresIn: TOKEN_LIFETIME_SECONDS,
});

// The upper bound keeps an attacker from forcing expensive hashes of huge inputs.
const credentialsSchema = z.object({
  email: z.email().max(254),
  password: z.string().min(12).max(128),
});

const loginSchema = z.object({
  email: z.string().max(254),
  password: z.string().max(128),
  totpCode: z.string().regex(/^\d{6}$/),
});

const serviceSchema = z.object({
  clientId: z.string().max(64),
  clientSecret: z.string().max(256),
});
