import { generateTotp } from "../crypto/totp";
import {
  decryptSymmetricBytes,
  decryptSymmetricString,
  encryptSymmetricBytes,
  encryptSymmetricString,
  sha256Base64,
} from "../crypto/bitwarden-crypto";

// On update, an omitted optional field keeps the stored value.
export interface LoginWriteInput {
  name: string;
  username: string;
  password: string;
  uri?: string;
  notes?: string;
  favorite?: boolean;
  /** Authenticator key: Base32 secret or otpauth://totp URI. */
  totp?: string;
}

export async function createEncryptedLogin(
  input: LoginWriteInput,
  userKey: Uint8Array,
): Promise<Record<string, unknown>> {
  const clean = await validateLoginInput(input);
  const itemKey = crypto.getRandomValues(new Uint8Array(64));
  try {
    return {
      type: 1,
      folderId: null,
      organizationId: null,
      key: await encryptSymmetricBytes(itemKey, userKey),
      name: await encryptSymmetricString(clean.name, itemKey),
      notes: clean.notes ? await encryptSymmetricString(clean.notes, itemKey) : null,
      favorite: clean.favorite === true,
      reprompt: 0,
      fields: [],
      passwordHistory: [],
      login: {
        username: await encryptOptional(clean.username, itemKey),
        password: await encryptOptional(clean.password, itemKey),
        passwordRevisionDate: null,
        totp: await encryptOptional(clean.totp, itemKey),
        uris: clean.uri ? [await encryptedUri(clean.uri, null, itemKey)] : [],
        autofillOnPageLoad: null,
        fido2Credentials: [],
      },
    };
  } finally {
    itemKey.fill(0);
  }
}

export async function updateEncryptedLogin(
  rawCipher: Record<string, unknown>,
  input: LoginWriteInput,
  userKey: Uint8Array,
): Promise<Record<string, unknown>> {
  const clean = await validateLoginInput(input);
  if (property(rawCipher, "OrganizationId", "organizationId")) {
    throw new Error("Editing organization-owned logins is not supported in this MVP.");
  }
  const encryptedKey = stringProperty(rawCipher, "Key", "key");
  const itemKey = encryptedKey ? await decryptSymmetricBytes(encryptedKey, userKey) : userKey;
  try {
    const rawLogin = recordProperty(rawCipher, "Login", "login") ?? {};
    const rawPassword = stringProperty(rawLogin, "Password", "password");
    const passwordChanged = await replacesPassword(rawPassword, clean.password, itemKey);
    const history = arrayProperty(rawCipher, "PasswordHistory", "passwordHistory").map(historyEntry);
    if (passwordChanged && rawPassword) {
      history.unshift({ password: rawPassword, lastUsedDate: new Date().toISOString() });
    }
    const rawUris: unknown[] = arrayProperty(rawLogin, "Uris", "uris").map(uriEntry);
    let uris = rawUris;
    if (clean.uri !== undefined) {
      // Only the first stored URI is edited; the rest are already encrypted under the item key.
      const first = rawUris[0] as { match: unknown } | undefined;
      uris = [...(clean.uri ? [await encryptedUri(clean.uri, first?.match ?? null, itemKey)] : []), ...rawUris.slice(1)];
    }
    return {
      type: numberProperty(rawCipher, "Type", "type") ?? 1,
      folderId: property(rawCipher, "FolderId", "folderId") ?? null,
      organizationId: null,
      key: encryptedKey ?? null,
      name: await encryptSymmetricString(clean.name, itemKey),
      notes:
        clean.notes === undefined
          ? (property(rawCipher, "Notes", "notes") ?? null)
          : await encryptOptional(clean.notes, itemKey),
      favorite: clean.favorite ?? property(rawCipher, "Favorite", "favorite") === true,
      reprompt: numberProperty(rawCipher, "Reprompt", "reprompt") ?? 0,
      fields: property(rawCipher, "Fields", "fields") ?? [],
      passwordHistory: history.slice(0, MAX_PASSWORD_HISTORY),
      attachments: property(rawCipher, "Attachments", "attachments") ?? null,
      lastKnownRevisionDate: property(rawCipher, "RevisionDate", "revisionDate") ?? null,
      // Newer Vaultwarden unarchives an item when this is missing.
      archivedDate: property(rawCipher, "ArchivedDate", "archivedDate") ?? null,
      login: {
        username: await encryptOptional(clean.username, itemKey),
        password: await encryptOptional(clean.password, itemKey),
        passwordRevisionDate: passwordChanged
          ? new Date().toISOString()
          : (property(rawLogin, "PasswordRevisionDate", "passwordRevisionDate") ?? null),
        totp: clean.totp
          ? await encryptSymmetricString(clean.totp, itemKey)
          : (property(rawLogin, "Totp", "totp") ?? null),
        uris,
        fido2Credentials: property(rawLogin, "Fido2Credentials", "fido2Credentials") ?? [],
        autofillOnPageLoad: property(rawLogin, "AutofillOnPageLoad", "autofillOnPageLoad") ?? null,
      },
    };
  } finally {
    if (encryptedKey) {
      itemKey.fill(0);
    }
  }
}

const MAX_PASSWORD_HISTORY = 5;

const encryptOptional = async (value: string | undefined, key: Uint8Array) =>
  value ? await encryptSymmetricString(value, key) : null;

async function encryptedUri(uri: string, match: unknown, key: Uint8Array) {
  return {
    uri: await encryptSymmetricString(uri, key),
    match,
    uriChecksum: await encryptSymmetricString(await sha256Base64(uri), key),
  };
}

// True when a stored, decryptable, non-empty password is being replaced by a different one.
async function replacesPassword(stored: string | undefined, next: string, key: Uint8Array) {
  if (!stored) return false;
  try {
    const old = await decryptSymmetricString(stored, key);
    return old !== "" && old !== next;
  } catch {
    return false;
  }
}

// Echo stored entries with one key casing so the server never sees both spellings.
function uriEntry(raw: unknown) {
  const entry = isRecord(raw) ? raw : {};
  return {
    uri: property(entry, "Uri", "uri") ?? null,
    match: property(entry, "Match", "match") ?? null,
    uriChecksum: property(entry, "UriChecksum", "uriChecksum") ?? null,
  };
}
function historyEntry(raw: unknown) {
  const entry = isRecord(raw) ? raw : {};
  return {
    password: property(entry, "Password", "password") ?? null,
    lastUsedDate: property(entry, "LastUsedDate", "lastUsedDate") ?? null,
  };
}
function arrayProperty(source: Record<string, unknown>, pascal: string, camel: string): unknown[] {
  const value = property(source, pascal, camel);
  return Array.isArray(value) ? value : [];
}
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function validateLoginInput(input: LoginWriteInput): Promise<LoginWriteInput> {
  const name = input.name.trim();
  const username = input.username.trim();
  const password = input.password;
  const notes = input.notes?.trim();
  const uri = input.uri === undefined ? undefined : normalizeUri(input.uri);
  const totp = input.totp?.trim() || undefined;
  if (!name || name.length > 1_000) throw new Error("Enter a login name up to 1,000 characters.");
  if (username.length > 1_000) throw new Error("Username is too long.");
  if (password.length > 10_000) throw new Error("Password is too long.");
  if (notes && notes.length > 10_000) throw new Error("Notes are too long.");
  if (totp) {
    await generateTotp(totp).catch(() => {
      throw new Error("Enter a valid authenticator key (Base32 secret or otpauth:// URI).");
    });
  }
  return {
    name,
    username,
    password,
    ...(uri === undefined ? {} : { uri }),
    ...(notes === undefined ? {} : { notes }),
    ...(input.favorite === undefined ? {} : { favorite: input.favorite === true }),
    ...(totp ? { totp } : {}),
  };
}

function normalizeUri(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) return "";
  const candidate = trimmed.includes("://") ? trimmed : `https://${trimmed}`;
  let parsed: URL;
  try {
    parsed = new URL(candidate);
  } catch {
    throw new Error("Enter a valid website URL.");
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new Error("Website URLs must use HTTPS or HTTP.");
  }
  return parsed.href;
}

function property(source: Record<string, unknown>, pascal: string, camel: string): unknown {
  return source[pascal] ?? source[camel];
}
function stringProperty(source: Record<string, unknown>, pascal: string, camel: string) {
  const value = property(source, pascal, camel);
  return typeof value === "string" ? value : undefined;
}
function numberProperty(source: Record<string, unknown>, pascal: string, camel: string) {
  const value = property(source, pascal, camel);
  return typeof value === "number" ? value : undefined;
}
function recordProperty(source: Record<string, unknown>, pascal: string, camel: string) {
  const value = property(source, pascal, camel);
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}
