const { describe, test, expect, beforeEach, afterEach } = require("bun:test");
const { writeFileSync, mkdirSync, rmSync } = require("node:fs");
const { join } = require("node:path");
const { loadSecrets, parseEnvFile } = require("../src/env-loader");

const TEST_DIR = join(__dirname, ".tmp-env-test");

beforeEach(() => {
  mkdirSync(TEST_DIR, { recursive: true });
});

afterEach(() => {
  rmSync(TEST_DIR, { recursive: true, force: true });
});

describe("parseEnvFile", () => {
  test("parses KEY=VALUE pairs", () => {
    const pairs = parseEnvFile("FOO=bar\nBAZ=qux");
    expect(pairs).toEqual([
      { key: "FOO", value: "bar" },
      { key: "BAZ", value: "qux" },
    ]);
  });

  test("handles double-quoted values", () => {
    const pairs = parseEnvFile('KEY="hello world"');
    expect(pairs[0].value).toBe("hello world");
  });

  test("handles single-quoted values", () => {
    const pairs = parseEnvFile("KEY='hello world'");
    expect(pairs[0].value).toBe("hello world");
  });

  test("skips comments", () => {
    const pairs = parseEnvFile("# this is a comment\nKEY=value");
    expect(pairs).toHaveLength(1);
    expect(pairs[0].key).toBe("KEY");
  });

  test("skips blank lines", () => {
    const pairs = parseEnvFile("KEY1=val1\n\n\nKEY2=val2");
    expect(pairs).toHaveLength(2);
  });

  test("handles export prefix", () => {
    const pairs = parseEnvFile("export MY_VAR=hello");
    expect(pairs[0]).toEqual({ key: "MY_VAR", value: "hello" });
  });

  test("handles inline comments for unquoted values", () => {
    const pairs = parseEnvFile("KEY=value # a comment");
    expect(pairs[0].value).toBe("value");
  });

  test("preserves # in quoted values", () => {
    const pairs = parseEnvFile('KEY="value # not a comment"');
    expect(pairs[0].value).toBe("value # not a comment");
  });

  test("handles lines without =", () => {
    const pairs = parseEnvFile("NOEQUALSSIGN");
    expect(pairs).toHaveLength(0);
  });

  test("handles empty value", () => {
    const pairs = parseEnvFile("KEY=");
    expect(pairs[0]).toEqual({ key: "KEY", value: "" });
  });
});

describe("loadSecrets", () => {
  test("loads secrets from .env file", () => {
    writeFileSync(join(TEST_DIR, ".env"), "API_KEY=my-secret-api-key-1234\n");
    const { values, valueToName } = loadSecrets([".env"], TEST_DIR);
    expect(values.has("my-secret-api-key-1234")).toBe(true);
    expect(valueToName.get("my-secret-api-key-1234")).toBe("API_KEY");
  });

  test("skips values shorter than minLength", () => {
    writeFileSync(join(TEST_DIR, ".env"), "PORT=3000\nSHORT=abc\nLONG=abcdefghijklmnop\n");
    const { values } = loadSecrets([".env"], TEST_DIR, 8);
    expect(values.has("3000")).toBe(false);
    expect(values.has("abc")).toBe(false);
    expect(values.has("abcdefghijklmnop")).toBe(true);
  });

  test("skips safe env prefixes", () => {
    writeFileSync(
      join(TEST_DIR, ".env"),
      "NEXT_PUBLIC_URL=https://example.com\nSECRET_KEY=super-secret-value-1234\n"
    );
    const { values } = loadSecrets([".env"], TEST_DIR, 8, ["NEXT_PUBLIC_"]);
    expect(values.has("https://example.com")).toBe(false);
    expect(values.has("super-secret-value-1234")).toBe(true);
  });

  test("loads from multiple files", () => {
    writeFileSync(join(TEST_DIR, ".env"), "KEY1=value-one-long-enough\n");
    writeFileSync(join(TEST_DIR, ".env.local"), "KEY2=value-two-long-enough\n");
    const { values } = loadSecrets([".env", ".env.local"], TEST_DIR);
    expect(values.has("value-one-long-enough")).toBe(true);
    expect(values.has("value-two-long-enough")).toBe(true);
  });

  test("handles missing files gracefully", () => {
    const { values } = loadSecrets([".env", ".env.nonexistent"], TEST_DIR);
    expect(values.size).toBe(0);
  });

  test("skips multiple safe prefixes", () => {
    writeFileSync(
      join(TEST_DIR, ".env"),
      [
        "PUBLIC_URL=https://example.com",
        "VITE_API_URL=https://api.example.com",
        "REACT_APP_NAME=my-react-app-name",
        "EXPO_PUBLIC_KEY=expo-public-key-value",
        "PRIVATE_KEY=private-key-value-secret",
      ].join("\n")
    );
    const prefixes = ["PUBLIC_", "NEXT_PUBLIC_", "VITE_", "REACT_APP_", "EXPO_PUBLIC_"];
    const { values } = loadSecrets([".env"], TEST_DIR, 8, prefixes);
    expect(values.has("https://example.com")).toBe(false);
    expect(values.has("https://api.example.com")).toBe(false);
    expect(values.has("my-react-app-name")).toBe(false);
    expect(values.has("expo-public-key-value")).toBe(false);
    expect(values.has("private-key-value-secret")).toBe(true);
  });
});
