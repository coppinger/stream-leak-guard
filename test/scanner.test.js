const { describe, test, expect } = require("bun:test");
const { scanForSecrets, sanitizeForOutput, isAssignmentContext, redactSecrets } = require("../src/scanner");
const { SECRET_PATTERNS } = require("../src/patterns");

describe("scanForSecrets", () => {
  describe("exact value matching", () => {
    test("detects exact secret value in text", () => {
      const values = new Set(["my-super-secret-key-12345"]);
      const valueToName = new Map([["my-super-secret-key-12345", "API_KEY"]]);
      const result = scanForSecrets(
        "curl -H 'Authorization: Bearer my-super-secret-key-12345'",
        values,
        [],
        valueToName
      );
      expect(result.found).toBe(true);
      expect(result.matches[0].name).toBe("env:API_KEY");
    });

    test("returns false when no match", () => {
      const values = new Set(["my-super-secret-key-12345"]);
      const result = scanForSecrets("echo hello world", values, []);
      expect(result.found).toBe(false);
    });

    test("handles empty text", () => {
      const result = scanForSecrets("", new Set(["secret"]));
      expect(result.found).toBe(false);
    });

    test("handles null text", () => {
      const result = scanForSecrets(null, new Set(["secret"]));
      expect(result.found).toBe(false);
    });
  });

  describe("pattern matching", () => {
    test("detects AWS access key", () => {
      const result = scanForSecrets("AKIAIOSFODNN7EXAMPLE1", null, SECRET_PATTERNS);
      expect(result.found).toBe(true);
      expect(result.matches[0].name).toBe("AWS Access Key ID");
    });

    test("detects GitHub personal access token", () => {
      const result = scanForSecrets(
        "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
        null,
        SECRET_PATTERNS
      );
      expect(result.found).toBe(true);
      expect(result.matches[0].name).toBe("GitHub Personal Access Token");
    });

    test("detects Anthropic API key", () => {
      const result = scanForSecrets(
        "sk-ant-api03-abcdefghijklmnopqrstuvwxyz",
        null,
        SECRET_PATTERNS
      );
      expect(result.found).toBe(true);
      expect(result.matches[0].name).toBe("Anthropic API Key");
    });

    test("detects Stripe secret key", () => {
      // Constructed at runtime to avoid triggering GitHub push protection
      const testKey = "sk_" + "live_" + "00000000000000FAKE0KEY000";
      const result = scanForSecrets(
        testKey,
        null,
        SECRET_PATTERNS
      );
      expect(result.found).toBe(true);
      expect(result.matches[0].name).toBe("Stripe Secret Key");
    });

    test("detects Slack bot token", () => {
      const result = scanForSecrets(
        "xoxb-1234567890123-abcdefghij",
        null,
        SECRET_PATTERNS
      );
      expect(result.found).toBe(true);
      expect(result.matches[0].name).toBe("Slack Bot Token");
    });

    test("detects private key header", () => {
      const result = scanForSecrets(
        "-----BEGIN RSA PRIVATE KEY-----",
        null,
        SECRET_PATTERNS
      );
      expect(result.found).toBe(true);
      expect(result.matches[0].name).toBe("Private Key");
    });

    test("detects database URL with password", () => {
      const result = scanForSecrets(
        "postgres://user:password123@localhost:5432/mydb",
        null,
        SECRET_PATTERNS
      );
      expect(result.found).toBe(true);
      expect(result.matches[0].name).toBe("Database URL with Password");
    });

    test("detects Google API key", () => {
      const result = scanForSecrets(
        "AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ0123456",
        null,
        SECRET_PATTERNS
      );
      expect(result.found).toBe(true);
      expect(result.matches[0].name).toBe("Google API Key");
    });

    test("detects npm token", () => {
      const result = scanForSecrets(
        "npm_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
        null,
        SECRET_PATTERNS
      );
      expect(result.found).toBe(true);
      expect(result.matches[0].name).toBe("npm Token");
    });

    test("detects SendGrid API key", () => {
      const result = scanForSecrets(
        "SG.abcdefghijklmnopqrstuv.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrs",
        null,
        SECRET_PATTERNS
      );
      expect(result.found).toBe(true);
      expect(result.matches[0].name).toBe("SendGrid API Key");
    });

    test("does not match normal text", () => {
      const result = scanForSecrets(
        "npm install express && node app.js",
        null,
        SECRET_PATTERNS
      );
      expect(result.found).toBe(false);
    });
  });

  describe("tooGeneric patterns", () => {
    test("skips tooGeneric patterns outside assignment context", () => {
      // A JWT-looking string not in assignment context
      const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
      const result = scanForSecrets(jwt, null, SECRET_PATTERNS);
      // The Supabase pattern may or may not match, but the JWT generic should not
      const jwtMatch = result.matches.find((m) => m.name === "JSON Web Token");
      expect(jwtMatch).toBeUndefined();
    });

    test("matches tooGeneric patterns in assignment context", () => {
      const text = 'secret = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"';
      const result = scanForSecrets(text, null, SECRET_PATTERNS);
      expect(result.found).toBe(true);
    });
  });

  describe("custom patterns", () => {
    test("matches custom regex patterns", () => {
      const customPatterns = [{ regex: "CUSTOM_[A-Z]{10}", name: "Custom Key" }];
      const result = scanForSecrets("CUSTOM_ABCDEFGHIJ", null, [], null, customPatterns);
      expect(result.found).toBe(true);
      expect(result.matches[0].name).toBe("Custom Key");
    });

    test("handles invalid custom regex gracefully", () => {
      const customPatterns = [{ regex: "[invalid(", name: "Bad Pattern" }];
      const result = scanForSecrets("some text", null, [], null, customPatterns);
      expect(result.found).toBe(false);
    });
  });
});

describe("sanitizeForOutput", () => {
  test("replaces secret values with [REDACTED]", () => {
    const values = new Set(["supersecret123"]);
    const result = sanitizeForOutput(
      "Found value supersecret123 in command",
      values
    );
    expect(result).toBe("Found value [REDACTED] in command");
  });

  test("replaces multiple occurrences", () => {
    const values = new Set(["secret1"]);
    const result = sanitizeForOutput("secret1 and secret1 again", values);
    expect(result).toBe("[REDACTED] and [REDACTED] again");
  });

  test("handles null message", () => {
    expect(sanitizeForOutput(null, new Set(["secret"]))).toBeNull();
  });

  test("handles null values", () => {
    expect(sanitizeForOutput("hello", null)).toBe("hello");
  });
});

describe("isAssignmentContext", () => {
  test("detects = assignment", () => {
    const text = 'SECRET_KEY = "value_here"';
    const idx = text.indexOf("value_here");
    expect(isAssignmentContext(text, idx)).toBe(true);
  });

  test("detects : assignment (JSON-like)", () => {
    const text = '"api_key": "value_here"';
    const idx = text.indexOf("value_here");
    expect(isAssignmentContext(text, idx)).toBe(true);
  });

  test("rejects non-assignment context", () => {
    const text = "echo value_here";
    const idx = text.indexOf("value_here");
    expect(isAssignmentContext(text, idx)).toBe(false);
  });
});

describe("redactSecrets", () => {
  describe("exact value redaction", () => {
    test("replaces exact secret values with [REDACTED:VAR_NAME]", () => {
      const values = new Set(["mysecretvalue12345678"]);
      const valueToName = new Map([["mysecretvalue12345678", "API_KEY"]]);
      const { redacted, redactionCount } = redactSecrets(
        "output: mysecretvalue12345678",
        values,
        valueToName
      );
      expect(redacted).toBe("output: [REDACTED:API_KEY]");
      expect(redactionCount).toBe(1);
    });

    test("replaces multiple occurrences", () => {
      const values = new Set(["secretabc12345678"]);
      const valueToName = new Map([["secretabc12345678", "TOKEN"]]);
      const { redacted, redactionCount } = redactSecrets(
        "secretabc12345678 and secretabc12345678",
        values,
        valueToName
      );
      expect(redacted).toBe("[REDACTED:TOKEN] and [REDACTED:TOKEN]");
      expect(redactionCount).toBe(2);
    });

    test("replaces longest values first to avoid partial corruption", () => {
      const values = new Set(["short1234567", "short1234567_extended"]);
      const valueToName = new Map([
        ["short1234567", "SHORT"],
        ["short1234567_extended", "LONG"],
      ]);
      const { redacted } = redactSecrets(
        "value: short1234567_extended",
        values,
        valueToName
      );
      expect(redacted).toBe("value: [REDACTED:LONG]");
    });

    test("uses UNKNOWN when valueToName is missing", () => {
      const values = new Set(["mysecretvalue12345678"]);
      const { redacted } = redactSecrets("mysecretvalue12345678", values, null);
      expect(redacted).toBe("[REDACTED:UNKNOWN]");
    });
  });

  describe("pattern-based redaction", () => {
    test("redacts known patterns like GitHub PATs", () => {
      const { redacted, redactionCount } = redactSecrets(
        "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
        null,
        null,
        SECRET_PATTERNS
      );
      expect(redactionCount).toBeGreaterThan(0);
      expect(redacted).toContain("[REDACTED:");
      expect(redacted).not.toContain("ghp_ABCDEFGHIJKLMNOP");
    });

    test("redacts AWS access keys", () => {
      const { redacted } = redactSecrets(
        "key: AKIAIOSFODNN7EXAMPLE1",
        null,
        null,
        SECRET_PATTERNS
      );
      expect(redacted).toContain("[REDACTED:AWS Access Key ID]");
    });

    test("redacts database URLs", () => {
      const { redacted } = redactSecrets(
        "postgres://user:password123@localhost:5432/mydb",
        null,
        null,
        SECRET_PATTERNS
      );
      expect(redacted).toContain("[REDACTED:");
    });
  });

  describe("custom patterns", () => {
    test("redacts custom patterns", () => {
      const custom = [{ regex: "CUSTOM_[A-Z]{10}", name: "Custom Key" }];
      const { redacted, redactionCount } = redactSecrets(
        "key: CUSTOM_ABCDEFGHIJ",
        null,
        null,
        [],
        custom
      );
      expect(redactionCount).toBe(1);
      expect(redacted).toBe("key: [REDACTED:Custom Key]");
    });

    test("handles invalid custom regex gracefully", () => {
      const custom = [{ regex: "[invalid(", name: "Bad" }];
      const { redacted, redactionCount } = redactSecrets(
        "some text",
        null,
        null,
        [],
        custom
      );
      expect(redactionCount).toBe(0);
      expect(redacted).toBe("some text");
    });
  });

  describe("edge cases", () => {
    test("returns unchanged for null/empty text", () => {
      expect(redactSecrets("", null, null).redacted).toBe("");
      expect(redactSecrets(null, null, null).redacted).toBeNull();
    });

    test("returns unchanged for binary content (null bytes)", () => {
      const binary = "some\0binary\0content";
      const values = new Set(["binary"]);
      const { redacted, redactionCount } = redactSecrets(binary, values, null);
      expect(redacted).toBe(binary);
      expect(redactionCount).toBe(0);
    });

    test("skips pattern scanning for large output (>1MB)", () => {
      // Create a large string with an AWS key pattern
      const largePrefix = "x".repeat(1_000_001);
      const text = largePrefix + "AKIAIOSFODNN7EXAMPLE1";
      const { redacted } = redactSecrets(text, null, null, SECRET_PATTERNS);
      // Pattern scanning skipped — AWS key should NOT be redacted
      expect(redacted).toContain("AKIAIOSFODNN7EXAMPLE1");
    });

    test("still does exact matching for large output", () => {
      const largePrefix = "x".repeat(1_000_001);
      const values = new Set(["mysecretvalue12345678"]);
      const valueToName = new Map([["mysecretvalue12345678", "KEY"]]);
      const text = largePrefix + "mysecretvalue12345678";
      const { redacted, redactionCount } = redactSecrets(text, values, valueToName, SECRET_PATTERNS);
      expect(redactionCount).toBe(1);
      expect(redacted).not.toContain("mysecretvalue12345678");
    });

    test("returns zero redactions for clean text", () => {
      const values = new Set(["mysecretvalue12345678"]);
      const { redacted, redactionCount } = redactSecrets(
        "npm test && echo done",
        values,
        null,
        SECRET_PATTERNS
      );
      expect(redactionCount).toBe(0);
      expect(redacted).toBe("npm test && echo done");
    });
  });
});
