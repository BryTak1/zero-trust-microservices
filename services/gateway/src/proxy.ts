import type { Request, Response } from "express";

export type Upstream = {
  readonly prefix: string;
  readonly target: string;
};

// Resolves a public path to an upstream URL, or undefined when no upstream owns it.
export const resolveUpstream = (
  upstreams: readonly Upstream[],
  path: string,
): string | undefined => {
  const upstream = upstreams.find(
    ({ prefix }) => path === prefix || path.startsWith(`${prefix}/`),
  );
  if (!upstream) {
    return undefined;
  }
  const rest = path.slice(upstream.prefix.length);
  // Only plain segments are forwarded, so "..", encoded slashes and similar cannot
  // reach an upstream path that the policy check never saw.
  return SAFE_REST.test(rest) ? `${upstream.target}${rest}` : undefined;
};

export const forward = async (
  req: Request,
  res: Response,
  targetUrl: string,
): Promise<void> => {
  const query = req.originalUrl.includes("?")
    ? req.originalUrl.slice(req.originalUrl.indexOf("?"))
    : "";
  const hasBody = req.method !== "GET" && req.method !== "HEAD";
  const upstream = await fetch(`${targetUrl}${query}`, {
    method: req.method,
    headers: {
      ...(hasBody ? { "content-type": "application/json" } : {}),
      ...(req.headers.authorization
        ? { authorization: req.headers.authorization }
        : {}),
    },
    body: hasBody ? JSON.stringify(req.body ?? {}) : undefined,
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });
  res
    .status(upstream.status)
    .type(upstream.headers.get("content-type") ?? "application/json")
    .send(await upstream.text());
};

const SAFE_REST = /^(\/[A-Za-z0-9_-]+)*$/;
const REQUEST_TIMEOUT_MS = 5000;
