import { describe, expect, it } from "vitest";

import { generatePassword } from "../src/crypto/password-generator";

describe("password generator", () => {
  it("uses every selected character class", () => {
    const password = generatePassword({
      length: 32,
      uppercase: true,
      lowercase: true,
      numbers: true,
      symbols: true,
    });

    expect(password).toHaveLength(32);
    expect(password).toMatch(/[A-Z]/);
    expect(password).toMatch(/[a-z]/);
    expect(password).toMatch(/[0-9]/);
    expect(password).toMatch(/[!@#$%^&*_.+=-]/);
  });

  it("draws symbols only from the allowed list", () => {
    for (let run = 0; run < 20; run += 1) {
      const password = generatePassword({ length: 40, uppercase: false, lowercase: true, numbers: false, symbols: true, symbolSet: "_-" });
      expect(password).toMatch(/^[a-z_-]+$/);
      expect(password).toMatch(/[_-]/);
    }
  });

  it("rejects an empty character selection", () => {
    expect(() =>
      generatePassword({
        length: 20,
        uppercase: false,
        lowercase: false,
        numbers: false,
        symbols: false,
      }),
    ).toThrow("Select at least one character type");
  });
});
