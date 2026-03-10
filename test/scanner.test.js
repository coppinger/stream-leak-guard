const { describe, test, expect } = require("bun:test");
const { scanForSecrets, sanitizeForOutput, isAssignmentContext } = require("../src/scanner");
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
