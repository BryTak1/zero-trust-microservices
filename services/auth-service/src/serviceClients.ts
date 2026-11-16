import { createHash, timingSafeEqual } from "node:crypto";
import type { Principal } from "@zt/common";

export type ServiceClients = Readonly<Record<string, string>>;

export const authenticateService = (
  clients: ServiceClients,
  clientId: string,
  clientSecret: string,
): Principal | undefined => {
  const expected = Object.hasOwn(clients, clientId) ? clients[clientId] : undefined;
  // Hashing first gives equal-length inputs, which timingSafeEqual requires.
  const matches = timingSafeEqual(digest(clientSecret), digest(expected ?? ""));
  return expected && matches ? { id: clientId, role: "service" } : undefined;
};

const digest = (value: string): Buffer =>
  createHash("sha256").update(value).digest();
