import type { Principal } from "@zt/common";

export type AccessRequest = {
  readonly principal: Principal | undefined;
  readonly method: string;
  readonly path: string;
};

// New behaviour is added by writing another Rule; evaluate never needs to change.
export type Rule = {
  readonly name: string;
  readonly effect: "allow" | "deny";
  readonly matches: (request: AccessRequest) => boolean;
};

export type Decision = {
  readonly allowed: boolean;
  readonly rule: string;
};

export const DEFAULT_DENY = "default-deny";

// A matching deny always wins, and a request that matches nothing is denied.
export const evaluate = (
  rules: readonly Rule[],
  request: AccessRequest,
): Decision => {
  const matching = rules.filter((rule) => rule.matches(request));
  const deny = matching.find((rule) => rule.effect === "deny");
  if (deny) {
    return { allowed: false, rule: deny.name };
  }
  const allow = matching[0];
  return allow
    ? { allowed: true, rule: allow.name }
    : { allowed: false, rule: DEFAULT_DENY };
};
