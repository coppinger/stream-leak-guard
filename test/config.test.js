const { describe, test, expect, beforeEach, afterEach } = require("bun:test");
const { writeFileSync, mkdirSync, rmSync } = require("node:fs");
const { join } = require("node:path");
const { loadConfig, DEFAULTS } = require("../src/config");

const TEST_DIR = join(__dirname, ".tmp-config-test");

beforeEach(() => {
  mkdirSync(TEST_DIR, { recursive: true });
});

afterEach(() => {
  rmSync(TEST_DIR, { recursive: true, force: true });
});

describe("loadConfig", () => {
  test("returns defaults when no config file exists", () => {
    const config = loadConfig(TEST_DIR);
    expect(config.enabled).toBe(true);
    expect(config.envFiles).toEqual(DEFAULTS.envFiles);
    expect(config.minSecretLength).toBe(8);
    expect(config.safeEnvPrefixes).toEqual(DEFAULTS.safeEnvPrefixes);
  });

  test("merges partial config with defaults", () => {
    writeFileSync(
      join(TEST_DIR, ".streamguardrc.json"),
      JSON.stringify({ minSecretLength: 12, verbose: true })
    );
    const config = loadConfig(TEST_DIR);
    expect(config.minSecretLength).toBe(12);
    expect(config.verbose).toBe(true);
    expect(config.enabled).toBe(true); // from defaults
    expect(config.envFiles).toEqual(DEFAULTS.envFiles); // from defaults
  });

  test("overrides defaults with config values", () => {
    writeFileSync(
      join(TEST_DIR, ".streamguardrc.json"),
      JSON.stringify({
        enabled: false,
        envFiles: [".env.custom"],
      })
    );
    const config = loadConfig(TEST_DIR);
    expect(config.enabled).toBe(false);
    expect(config.envFiles).toEqual([".env.custom"]);
  });

  test("falls back to defaults on invalid JSON", () => {
    writeFileSync(join(TEST_DIR, ".streamguardrc.json"), "not valid json{{{");
    const config = loadConfig(TEST_DIR);
    expect(config.enabled).toBe(true);
    expect(config.envFiles).toEqual(DEFAULTS.envFiles);
  });

  test("handles custom patterns in config", () => {
    writeFileSync(
      join(TEST_DIR, ".streamguardrc.json"),
      JSON.stringify({
        customPatterns: [{ regex: "MY_CUSTOM_[A-Z]+", name: "My Custom" }],
      })
    );
    const config = loadConfig(TEST_DIR);
    expect(config.customPatterns).toHaveLength(1);
    expect(config.customPatterns[0].name).toBe("My Custom");
  });

  test("handles custom safe prefixes", () => {
    writeFileSync(
      join(TEST_DIR, ".streamguardrc.json"),
      JSON.stringify({
        safeEnvPrefixes: ["SAFE_", "OK_"],
      })
    );
    const config = loadConfig(TEST_DIR);
    expect(config.safeEnvPrefixes).toEqual(["SAFE_", "OK_"]);
  });
});
