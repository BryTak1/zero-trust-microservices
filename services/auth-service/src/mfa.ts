import { authenticator } from "otplib";

export type MfaProvider = {
  readonly generateSecret: () => string;
  readonly enrollmentUri: (email: string, secret: string) => string;
  readonly check: (code: string, secret: string) => boolean;
};

export const totpMfaProvider: MfaProvider = {
  generateSecret: () => authenticator.generateSecret(),
  enrollmentUri: (email, secret) =>
    authenticator.keyuri(email, "Zero Trust Demo", secret),
  check: (code, secret) => authenticator.check(code, secret),
};
