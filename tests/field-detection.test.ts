import { describe, expect, it } from "vitest";

import { looksLikeTotpField, looksLikeUsernameField } from "../src/site/field-detection";

const base = {
  type: "text",
  autocomplete: "",
  inputHint: "",
  contextHint: "",
  eligibleFieldCount: 1,
};

describe("username field detection", () => {
  it("recognizes the AWS-style username control", () => {
    expect(looksLikeUsernameField({
      ...base,
      autocomplete: "on",
      inputHint: "on username username username",
      contextHint: "Sign in Next",
    })).toBe(true);
  });

  it("recognizes generic single-field multi-step sign-in forms", () => {
    expect(looksLikeUsernameField({
      ...base,
      inputHint: "principal",
      contextHint: "/platform/tenant/login Continue",
    })).toBe(true);
  });

  it("recognizes identifier and associated-label signals", () => {
    expect(looksLikeUsernameField({ ...base, inputHint: "account identifier" })).toBe(true);
    expect(looksLikeUsernameField({ ...base, inputHint: "Corporate user ID" })).toBe(true);
  });

  it("does not treat search, OTP, or ambiguous multi-field controls as usernames", () => {
    expect(looksLikeUsernameField({ ...base, type: "search", inputHint: "search", contextHint: "Sign in" })).toBe(false);
    expect(looksLikeUsernameField({ ...base, inputHint: "verification code", contextHint: "Sign in" })).toBe(false);
    expect(looksLikeUsernameField({ ...base, inputHint: "customer", contextHint: "Sign in", eligibleFieldCount: 2 })).toBe(false);
  });
});

describe("totp field detection", () => {
  const totp = { type: "text", autocomplete: "", inputHint: "", maxLength: -1 };

  it("recognizes one-time-code autocomplete, labels, and names", () => {
    expect(looksLikeTotpField({ ...totp, autocomplete: "one-time-code" })).toBe(true);
    expect(looksLikeTotpField({ ...totp, inputHint: "Enter the 6-digit code from your authenticator app" })).toBe(true);
    expect(looksLikeTotpField({ ...totp, inputHint: "totp" })).toBe(true);
  });

  it("rejects promo, captcha, username, and single-digit boxes", () => {
    expect(looksLikeTotpField({ ...totp, inputHint: "promo code" })).toBe(false);
    expect(looksLikeTotpField({ ...totp, inputHint: "captcha code" })).toBe(false);
    expect(looksLikeTotpField({ ...totp, type: "email", inputHint: "email" })).toBe(false);
    expect(looksLikeTotpField({ ...totp, inputHint: "username" })).toBe(false);
    expect(looksLikeTotpField({ ...totp, autocomplete: "one-time-code", maxLength: 1 })).toBe(false);
  });
});

describe("looksLikeTotpField on real attribute names", () => {
  const field = (inputHint: string, extra: Partial<{ type: string; autocomplete: string; maxLength: number }> = {}) =>
    looksLikeTotpField({ type: "text", autocomplete: "", maxLength: -1, inputHint, ...extra });

  it("matches snake_case and camelCase 2FA names", () => {
    for (const hint of ["otp_code", "mfa_code", "login_otp", "otpcode", "mfacode", "totppin", "two_factor_token"]) {
      expect(field(hint), hint).toBe(true);
    }
  });

  it("does not take over username, client or token fields", () => {
    expect(field("client code")).toBe(false);
    expect(field("user code")).toBe(false);
    expect(field("access token")).toBe(false);
    expect(field("login code", { autocomplete: "username" })).toBe(false);
    expect(field("security code", { autocomplete: "cc-csc" })).toBe(false);
    expect(field("password", { type: "password", autocomplete: "current-password" })).toBe(false);
  });

  it("needs a code-shaped input for a bare code label", () => {
    expect(field("code")).toBe(false);
    expect(field("code", { maxLength: 6 })).toBe(true);
    expect(field("code", { type: "tel" })).toBe(true);
  });
});
