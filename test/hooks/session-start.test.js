const { describe, test, expect } = require("bun:test");
const { execFileSync } = require("node:child_process");
const { join } = require("node:path");

const CLI = join(__dirname, "../../bin/cli.js");

describe("session-start hook", () => {
  test("outputs valid JSON with safety context", () => {
    const result = execFileSync("node", [CLI, "--hook", "session-start"], {
      input: "{}",
      encoding: "utf-8",
    });
    const output = JSON.parse(result);
    expect(output.hookSpecificOutput).toBeDefined();
    expect(output.hookSpecificOutput.hookEventName).toBe("SessionStart");
    expect(output.hookSpecificOutput.additionalContext).toContain(
      "STREAMING SAFETY MODE ACTIVE"
    );
    expect(output.hookSpecificOutput.additionalContext).toContain("NEVER");
    expect(output.hookSpecificOutput.additionalContext).toContain("[REDACTED]");
  });

  test("includes key safety instructions", () => {
    const result = execFileSync("node", [CLI, "--hook", "session-start"], {
      input: "{}",
      encoding: "utf-8",
    });
    const output = JSON.parse(result);
    const ctx = output.hookSpecificOutput.additionalContext;
    expect(ctx).toContain("API keys");
    expect(ctx).toContain("tokens");
    expect(ctx).toContain("passwords");
  });
});
