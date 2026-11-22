export interface UsernameFieldSignals {
  type: string;
  autocomplete: string;
  inputHint: string;
  contextHint: string;
  eligibleFieldCount: number;
}

const supportedTypes = new Set(["", "text", "email", "tel", "search"]);
const explicitUsername = /user[\s_-]*(?:name|id)|login[\s_-]*(?:name|id)|e[\s_-]*mail|email|identifier|account[\s_-]*name/;
const nonCredential = /search|query|one[\s_-]*time|otp|verification|security[\s_-]*code|captcha|coupon|promo/;
const loginContext = /sign[\s_-]*in|log[\s_-]*in|login|authenticate|authentication|session|continue|next/;

export function looksLikeUsernameField(signals: UsernameFieldSignals): boolean {
  const type = signals.type.toLowerCase();
  if (!supportedTypes.has(type)) return false;

  const autocomplete = signals.autocomplete.toLowerCase();
  const inputHint = signals.inputHint.toLowerCase();
  if (["username", "email"].includes(autocomplete)) return true;
  if (nonCredential.test(inputHint)) return false;
  if (type === "email" || explicitUsername.test(inputHint)) return true;
  if (type === "tel" && /phone|mobile/.test(inputHint)) return true;

  // Multi-step sign-in pages often use a generic text/identifier control before
  // rendering the password step. Treat it as a username only when it is the
  // sole plausible field in an explicitly login-shaped context.
  return type !== "search" && signals.eligibleFieldCount === 1 && loginContext.test(signals.contextHint.toLowerCase());
}

export function canBeUsernameField(typeInput: string, hintInput: string): boolean {
  const type = typeInput.toLowerCase();
  return supportedTypes.has(type) && type !== "search" && !nonCredential.test(hintInput.toLowerCase());
}

export interface TotpFieldSignals {
  type: string;
  autocomplete: string;
  inputHint: string;
  maxLength: number;
}

const totpTypes = new Set(["", "text", "tel", "number", "password"]);
const credentialAutocomplete = /^(?:username|email|current-password|new-password|cc-.*)$/;
const notTotp = /captcha|coupon|promo|voucher|gift|discount|invite|referral|zip|postal|country|search|backup|recovery|user|client|access|account|email|card|cvv|cvc/;
// Substrings, not word matches: attribute names arrive as otp_code or lowercased otpCode.
const strongTotpHint = /otp|mfa|2fa|one[\s_-]*time|two[\s_-]*(?:factor|step)|multi[\s_-]*factor|authenticator|verification[\s_-]*code|security[\s_-]*code|auth[\s_-]*code/;
const weakTotpHint = /\bcode\b|\btoken\b/;

export function looksLikeTotpField(signals: TotpFieldSignals): boolean {
  const type = signals.type.toLowerCase();
  if (!totpTypes.has(type)) return false;
  // ponytail: split one-digit-per-box OTP inputs are not supported; fill the first box by hand or add per-box filling if needed.
  if (signals.maxLength > 0 && signals.maxLength < 6) return false;
  const autocomplete = signals.autocomplete.trim().toLowerCase();
  if (autocomplete.includes("one-time-code")) return true;
  if (credentialAutocomplete.test(autocomplete)) return false;
  const hint = signals.inputHint.toLowerCase();
  if (notTotp.test(hint)) return false;
  if (strongTotpHint.test(hint)) return true;
  // A bare "code"/"token" label needs a code-shaped input too.
  return weakTotpHint.test(hint) && (type === "tel" || type === "number" || (signals.maxLength >= 6 && signals.maxLength <= 10));
}
