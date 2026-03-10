const { describe, test, expect, beforeEach, afterEach } = require("bun:test");
const { execFileSync } = require("node:child_process");
const { writeFileSync, mkdirSync, rmSync } = require("node:fs");
const { join } = require("node:path");

const CLI = join(__dirname, "../../bin/cli.js");
const TEST_DIR = join(__dirname, ".tmp-hook-test");

function runHook(hookEvent, cwd = TEST_DIR) {
  try {
    const result = execFileSync("node", [CLI, "--hook", "pre-tool-use"], {
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

describe("pre-tool-use hook — Bash", () => {
  test("blocks bare `env` command", () => {
    const { output } = runHook({
      tool_name: "Bash",
      tool_input: { command: "env" },
    });
    expect(output.hookSpecificOutput.permissionDecision).toBe("deny");
    expect(output.hookSpecificOutput.permissionDecisionReason).toContain("env");
  });

  test("blocks `cat .env`", () => {
    const { output } = runHook({
      tool_name: "Bash",
      tool_input: { command: "cat .env" },
    });
    expect(output.hookSpecificOutput.permissionDecision).toBe("deny");
  });

  test("allows normal commands", () => {
    const { output } = runHook({
      tool_name: "Bash",
      tool_input: { command: "npm test" },
    });
    expect(output).toBeNull();
  });

  test("blocks commands containing secret values from .env", () => {
    writeFileSync(
      join(TEST_DIR, ".env"),
      "API_KEY=sk-ant-api03-mysupersecretkey123456\n"
    );
    const { output } = runHook({
      tool_name: "Bash",
      tool_input: {
        command: "curl -H 'Authorization: Bearer sk-ant-api03-mysupersecretkey123456' https://api.example.com",
      },
    });
    expect(output.hookSpecificOutput.permissionDecision).toBe("deny");
  });

  test("allows commands that don't contain secrets", () => {
    writeFileSync(join(TEST_DIR, ".env"), "API_KEY=mysecretkey1234567890\n");
    const { output } = runHook({
      tool_name: "Bash",
      tool_input: { command: "echo hello" },
    });
    expect(output).toBeNull();
  });
});

describe("pre-tool-use hook — Read", () => {
  test("blocks reading .env file", () => {
    const { output } = runHook({
      tool_name: "Read",
      tool_input: { file_path: "/home/user/project/.env" },
    });
    expect(output.hookSpecificOutput.permissionDecision).toBe("deny");
    expect(output.hookSpecificOutput.permissionDecisionReason).toContain(".env");
  });

  test("blocks reading .env.local", () => {
    const { output } = runHook({
      tool_name: "Read",
      tool_input: { file_path: "/home/user/project/.env.local" },
    });
    expect(output.hookSpecificOutput.permissionDecision).toBe("deny");
  });

  test("blocks reading credentials.json", () => {
    const { output } = runHook({
      tool_name: "Read",
      tool_input: { file_path: "/home/user/project/credentials.json" },
    });
    expect(output.hookSpecificOutput.permissionDecision).toBe("deny");
  });

  test("blocks reading .pem files", () => {
    const { output } = runHook({
      tool_name: "Read",
      tool_input: { file_path: "/home/user/project/server.pem" },
    });
    expect(output.hookSpecificOutput.permissionDecision).toBe("deny");
  });

  test("allows reading normal files", () => {
    const { output } = runHook({
      tool_name: "Read",
      tool_input: { file_path: "/home/user/project/package.json" },
    });
    expect(output).toBeNull();
  });
});

describe("pre-tool-use hook — Write", () => {
  test("blocks writing content with secret values", () => {
    writeFileSync(
      join(TEST_DIR, ".env"),
      "DB_URL=postgres://admin:secretpass123@db.example.com:5432/mydb\n"
    );
    const { output } = runHook({
      tool_name: "Write",
      tool_input: {
        file_path: "/tmp/test.txt",
        content: "database: postgres://admin:secretpass123@db.example.com:5432/mydb",
      },
    });
    expect(output.hookSpecificOutput.permissionDecision).toBe("deny");
  });

  test("allows writing content without secrets", () => {
    const { output } = runHook({
      tool_name: "Write",
      tool_input: {
        file_path: "/tmp/test.txt",
        content: "hello world",
      },
    });
    expect(output).toBeNull();
  });
});

describe("pre-tool-use hook — Edit", () => {
  test("blocks edit with secret values in new_string", () => {
    writeFileSync(
      join(TEST_DIR, ".env"),
      "SECRET=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh\n"
    );
    const { output } = runHook({
      tool_name: "Edit",
      tool_input: {
        file_path: "/tmp/test.txt",
        old_string: "placeholder",
        new_string: "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh",
      },
    });
    expect(output.hookSpecificOutput.permissionDecision).toBe("deny");
  });

  test("allows edit without secrets", () => {
    const { output } = runHook({
      tool_name: "Edit",
      tool_input: {
        file_path: "/tmp/test.txt",
        old_string: "hello",
        new_string: "world",
      },
    });
    expect(output).toBeNull();
  });
});

describe("pre-tool-use hook — disabled", () => {
  test("allows everything when disabled", () => {
    writeFileSync(
      join(TEST_DIR, ".streamguardrc.json"),
      JSON.stringify({ enabled: false })
    );
    const { output } = runHook({
      tool_name: "Bash",
      tool_input: { command: "env" },
    });
    expect(output).toBeNull();
  });
});

describe("pre-tool-use hook — invalid input", () => {
  test("exits cleanly on invalid JSON input", () => {
    try {
      const result = execFileSync("node", [CLI, "--hook", "pre-tool-use"], {
        input: "not json",
        encoding: "utf-8",
        cwd: TEST_DIR,
      });
      // Should exit 0 (fail open)
      expect(true).toBe(true);
    } catch (err) {
      // Exit 0 is fine (fail open)
      expect(err.status).toBe(0);
    }
  });
});
