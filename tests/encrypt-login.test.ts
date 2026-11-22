import { describe, expect, it } from "vitest";

import { decryptSymmetricBytes, decryptSymmetricString, encryptSymmetricString, sha256Base64 } from "../src/crypto/bitwarden-crypto";
import { createEncryptedLogin, updateEncryptedLogin } from "../src/vault/encrypt-login";

describe("encrypted login writes", () => {
  it("creates an item-key protected personal cipher with a verifiable URI checksum", async () => {
    const userKey = crypto.getRandomValues(new Uint8Array(64));
    const payload = await createEncryptedLogin(
      {
        name: "Example",
        username: "person@example.com",
        password: "secret",
        uri: "https://example.com/login",
        notes: "personal",
        favorite: true,
      },
      userKey,
    );
    const itemKey = await decryptSymmetricBytes(payload.key as string, userKey);
    const login = payload.login as Record<string, unknown>;
    const uri = (login.uris as Array<Record<string, string>>)[0]!;

    await expect(decryptSymmetricString(payload.name as string, itemKey)).resolves.toBe("Example");
    await expect(decryptSymmetricString(login.username as string, itemKey)).resolves.toBe("person@example.com");
    await expect(decryptSymmetricString(login.password as string, itemKey)).resolves.toBe("secret");
    await expect(decryptSymmetricString(uri.uri!, itemKey)).resolves.toBe("https://example.com/login");
    await expect(decryptSymmetricString(uri.uriChecksum!, itemKey)).resolves.toBe(
      await sha256Base64("https://example.com/login"),
    );
    expect(payload.organizationId).toBeNull();
  });

  it("preserves protected login metadata while updating editable fields", async () => {
    const userKey = crypto.getRandomValues(new Uint8Array(64));
    const original = await createEncryptedLogin(
      { name: "Old", username: "old", password: "old-pass", uri: "https://old.example" },
      userKey,
    );
    const itemKey = await decryptSymmetricBytes(original.key as string, userKey);
    const totp = await encryptSymmetricString("otpauth://totp/test?secret=ABC", itemKey);
    const raw = { ...original, Id: "cipher-id", RevisionDate: "2026-08-01T00:00:00Z", Login: { ...(original.login as object), Totp: totp } };
    const updated = await updateEncryptedLogin(
      raw,
      { name: "New", username: "new", password: "new-pass", uri: "https://new.example" },
      userKey,
    );
    const login = updated.login as Record<string, unknown>;

    expect(login.totp).toBe(totp);
    expect(updated.lastKnownRevisionDate).toBe("2026-08-01T00:00:00Z");
    await expect(decryptSymmetricString(updated.name as string, itemKey)).resolves.toBe("New");
    await expect(decryptSymmetricString(login.password as string, itemKey)).resolves.toBe("new-pass");
  });

  it("refuses organization-owned cipher updates", async () => {
    const userKey = crypto.getRandomValues(new Uint8Array(64));
    await expect(
      updateEncryptedLogin(
        { organizationId: "org" },
        { name: "No", username: "", password: "", uri: "" },
        userKey,
      ),
    ).rejects.toThrow(/organization-owned/);
  });

  describe("partial updates", () => {
    const seed = "JBSWY3DPEHPK3PXP";
    const decrypt = (value: unknown, key: Uint8Array) => decryptSymmetricString(value as string, key);
    async function setup(extra: Record<string, unknown> = {}) {
      const userKey = crypto.getRandomValues(new Uint8Array(64));
      const original = await createEncryptedLogin(
        { name: "Site", username: "u", password: "old-pass", uri: "https://one.example", notes: "keep me", favorite: true, totp: seed },
        userKey,
      );
      const itemKey = await decryptSymmetricBytes(original.key as string, userKey);
      const second = {
        uri: await encryptSymmetricString("https://two.example", itemKey),
        match: 3,
        uriChecksum: await encryptSymmetricString(await sha256Base64("https://two.example"), itemKey),
      };
      const login = original.login as Record<string, unknown>;
      const first = { ...(login.uris as object[])[0]!, match: 1 };
      const raw: Record<string, unknown> = { ...original, login: { ...login, uris: [first, second] }, ...extra };
      return { userKey, itemKey, raw, login: raw.login as Record<string, unknown> };
    }
    const base = { name: "Site", username: "u", password: "old-pass" };

    it("round-trips a totp key on create and rejects an invalid one", async () => {
      const { userKey, itemKey, login } = await setup();
      await expect(decrypt(login.totp, itemKey)).resolves.toBe(seed);
      await expect(createEncryptedLogin({ ...base, totp: "not base32!" }, userKey)).rejects.toThrow(/authenticator key/);
      const none = await createEncryptedLogin({ ...base, totp: "  " }, userKey);
      expect((none.login as Record<string, unknown>).totp).toBeNull();
    });

    it("keeps notes, favorite, uris and totp when the input omits them", async () => {
      const { userKey, raw, login } = await setup({ archivedDate: "2026-01-01T00:00:00Z" });
      const updated = await updateEncryptedLogin(raw, base, userKey);
      const out = updated.login as Record<string, unknown>;
      expect(updated.notes).toBe(raw.notes);
      expect(updated.favorite).toBe(true);
      expect(updated.archivedDate).toBe("2026-01-01T00:00:00Z");
      expect(out.totp).toBe(login.totp);
      expect(out.uris).toEqual(login.uris);
      expect(out.passwordRevisionDate).toBeNull();
      expect(updated.passwordHistory).toEqual([]);
    });

    it("replaces only the first uri, keeping its match type and the second uri", async () => {
      const { userKey, itemKey, raw, login } = await setup();
      const updated = await updateEncryptedLogin(raw, { ...base, uri: "https://new.example" }, userKey);
      const uris = (updated.login as { uris: Array<Record<string, unknown>> }).uris;
      expect(uris).toHaveLength(2);
      await expect(decrypt(uris[0]!.uri, itemKey)).resolves.toBe("https://new.example/");
      await expect(decrypt(uris[0]!.uriChecksum, itemKey)).resolves.toBe(await sha256Base64("https://new.example/"));
      expect(uris[0]!.match).toBe(1);
      expect(uris[1]).toEqual((login.uris as object[])[1]);
      const dropped = await updateEncryptedLogin(raw, { ...base, uri: "" }, userKey);
      expect((dropped.login as { uris: unknown[] }).uris).toEqual([(login.uris as object[])[1]]);
    });

    it("replaces the totp key and keeps the stored one for an empty value", async () => {
      const { userKey, itemKey, raw, login } = await setup();
      const updated = await updateEncryptedLogin(raw, { ...base, totp: "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ" }, userKey);
      await expect(decrypt((updated.login as Record<string, unknown>).totp, itemKey)).resolves.toContain("GEZDGNBVGY3TQOJQ");
      const same = await updateEncryptedLogin(raw, { ...base, totp: "" }, userKey);
      expect((same.login as Record<string, unknown>).totp).toBe(login.totp);
      await expect(updateEncryptedLogin(raw, { ...base, totp: "bad!" }, userKey)).rejects.toThrow(/authenticator key/);
    });

    it("clears notes with an empty string and updates favorite", async () => {
      const { userKey, raw } = await setup();
      const updated = await updateEncryptedLogin(raw, { ...base, notes: "", favorite: false }, userKey);
      expect(updated.notes).toBeNull();
      expect(updated.favorite).toBe(false);
    });

    it("records the old password in history, capped at five entries", async () => {
      const { userKey, itemKey, raw, login } = await setup();
      const history = Array.from({ length: 5 }, (_, index) => ({ password: "h" + index, lastUsedDate: "2026-01-01T00:00:00Z" }));
      const updated = await updateEncryptedLogin({ ...raw, passwordHistory: history }, { ...base, password: "new-pass" }, userKey);
      const entries = updated.passwordHistory as Array<Record<string, string>>;
      expect(entries).toHaveLength(5);
      expect(entries[0]!.password).toBe(login.password);
      await expect(decrypt(entries[0]!.password, itemKey)).resolves.toBe("old-pass");
      expect(entries[1]!.password).toBe("h0");
      expect((updated.login as Record<string, unknown>).passwordRevisionDate).toEqual(expect.any(String));
      const unchanged = await updateEncryptedLogin(raw, base, userKey);
      expect(unchanged.passwordHistory).toEqual([]);
    });
  });
});
