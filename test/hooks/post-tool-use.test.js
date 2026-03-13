const { describe, test, expect, beforeEach, afterEach } = require("bun:test");
const { execFileSync } = require("node:child_process");
const { writeFileSync, mkdirSync, rmSync } = require("node:fs");
const { join } = require("node:path");

const CLI = join(__dirname, "../../bin/cli.js");
const TEST_DIR = join(__dirname, ".tmp-post-hook-test");

function runHook(hookEvent, cwd = TEST_DIR) {
  try {
    const result = execFileSync("node", [CLI, "--hook", "post-tool-use"], {
      input: JSON.stringify(hookEvent),
      encoding: "utf-8",
      cwd,
    });
    if (result.trim()) {
      return { exitCode: 0, output: JSON.parse(result) };
    }
    return { exitCode: 0, output: null };
  } catch (err) {
    return { exitCode: err.status, output: null };
  }
}

beforeEach(() => {
  mkdirSync(TEST_DIR, { recursive: true });
});

afterEach(() => {
  rmSync(TEST_DIR, { recursive: true, force: true });
});

describe("post-tool-use hook — Bash output redaction", () => {
  test("redacts secret values from stdout", () => {
    writeFileSync(
      join(TEST_DIR, ".env"),
      "API_KEY=sk-ant-api03-mysupersecretkey123456\n"
    );
    const { output } = runHook({
      tool_name: "Bash",
      tool_input: { command: "grep API_KEY .env" },
      tool_output: {
        stdout: "API_KEY=sk-ant-api03-mysupersecretkey123456",
        stderr: "",
      },
    });
    expect(output).not.toBeNull();
    expect(output.hookSpecificOutput.modifiedToolResult).toContain("[REDACTED:");
    expect(output.hookSpecificOutput.modifiedToolResult).not.toContain("sk-ant-api03-mysupersecretkey123456");
  });

  test("redacts secret values from stderr", () => {
    writeFileSync(
      join(TEST_DIR, ".env"),
      "DB_PASS=mysuperpassword12345678\n"
    );
    const { output } = runHook({
      tool_name: "Bash",
      tool_input: { command: "some-cmd" },
      tool_output: {
        stdout: "",
        stderr: "Error: connection failed with mysuperpassword12345678",
      },
    });
    expect(output).not.toBeNull();
    expect(output.hookSpecificOutput.modifiedToolResult).toContain("[REDACTED:");
    expect(output.hookSpecificOutput.modifiedToolResult).not.toContain("mysuperpassword12345678");
  });

  test("passes through clean output without modification", () => {
    writeFileSync(
      join(TEST_DIR, ".env"),
      "API_KEY=sk-ant-api03-mysupersecretkey123456\n"
    );
    const { output } = runHook({
      tool_name: "Bash",
      tool_input: { command: "ls -la" },
      tool_output: {
        stdout: "total 8\ndrwxr-xr-x 2 user user 4096 Jan 1 00:00 .\n",
        stderr: "",
      },
    });
    expect(output).toBeNull();
  });

  test("redacts pattern-matched secrets (e.g. GitHub PAT)", () => {
    // No .env needed — pattern matching should catch this
    const { output } = runHook({
      tool_name: "Bash",
      tool_input: { command: "cat some-file" },
      tool_output: {
        stdout: "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
        stderr: "",
      },
    });
    expect(output).not.toBeNull();
    expect(output.hookSpecificOutput.modifiedToolResult).toContain("[REDACTED:");
    expect(output.hookSpecificOutput.modifiedToolResult).not.toContain("ghp_ABCDEFGHIJKLMNOP");
  });
});

describe("post-tool-use hook — Read output redaction", () => {
  test("redacts secrets from Read tool output", () => {
    writeFileSync(
      join(TEST_DIR, ".env"),
      "SECRET_TOKEN=abcdefghijklmnopqrstuvwxyz123456\n"
    );
    const { output } = runHook({
      tool_name: "Read",
      tool_input: { file_path: "/some/file.txt" },
      tool_output: "contents include abcdefghijklmnopqrstuvwxyz123456 here",
    });
    expect(output).not.toBeNull();
    expect(output.hookSpecificOutput.modifiedToolResult).toContain("[REDACTED:");
    expect(output.hookSpecificOutput.modifiedToolResult).not.toContain("abcdefghijklmnopqrstuvwxyz123456");
  });

  test("handles Read tool output as object with content field", () => {
    writeFileSync(
      join(TEST_DIR, ".env"),
      "MY_SECRET=verylongsecretvalue12345678\n"
    );
    const { output } = runHook({
      tool_name: "Read",
      tool_input: { file_path: "/some/file.txt" },
      tool_output: { content: "data: verylongsecretvalue12345678" },
    });
    expect(output).not.toBeNull();
    expect(output.hookSpecificOutput.modifiedToolResult).not.toContain("verylongsecretvalue12345678");
  });
});

describe("post-tool-use hook — disabled", () => {
  test("passes through when disabled", () => {
    writeFileSync(
      join(TEST_DIR, ".streamguardrc.json"),
      JSON.stringify({ enabled: false })
    );
    writeFileSync(
      join(TEST_DIR, ".env"),
      "API_KEY=sk-ant-api03-mysupersecretkey123456\n"
    );
    const { output } = runHook({
      tool_name: "Bash",
      tool_input: { command: "cat .env" },
      tool_output: {
        stdout: "API_KEY=sk-ant-api03-mysupersecretkey123456",
        stderr: "",
      },
    });
    expect(output).toBeNull();
  });
});

describe("post-tool-use hook — fail-open", () => {
  test("exits cleanly on invalid JSON input", () => {
    try {
      const result = execFileSync("node", [CLI, "--hook", "post-tool-use"], {
        input: "not json",
        encoding: "utf-8",
        cwd: TEST_DIR,
      });
      // Should exit 0 (fail open)
      expect(true).toBe(true);
    } catch (err) {
      expect(err.status).toBe(0);
    }
  });

  test("exits cleanly with empty tool_output", () => {
    const { exitCode, output } = runHook({
      tool_name: "Bash",
      tool_input: { command: "true" },
      tool_output: null,
    });
    expect(exitCode).toBe(0);
    expect(output).toBeNull();
  });
});
