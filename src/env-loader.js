const { readFileSync } = require("node:fs");
const { join } = require("node:path");

/**
 * Parse a .env file into key-value pairs.
 * Handles: quotes, comments, blank lines, export prefix.
 */
function parseEnvFile(content) {
  const pairs = [];
  for (const rawLine of content.split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;

    // Strip optional "export " prefix
    const stripped = line.startsWith("export ") ? line.slice(7) : line;

    const eqIndex = stripped.indexOf("=");
    if (eqIndex === -1) continue;

    const key = stripped.slice(0, eqIndex).trim();
    let value = stripped.slice(eqIndex + 1).trim();

    // Remove surrounding quotes
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }

    // Strip inline comments (only for unquoted values)
    if (!stripped.slice(eqIndex + 1).trim().startsWith('"') &&
        !stripped.slice(eqIndex + 1).trim().startsWith("'")) {
      const commentIndex = value.indexOf(" #");
      if (commentIndex !== -1) {
        value = value.slice(0, commentIndex).trim();
      }
    }

    if (key) {
      pairs.push({ key, value });
    }
  }
  return pairs;
}

/**
 * Load secrets from .env files.
 * Returns { values: Set<string>, valueToName: Map<string, string> }
 */
function loadSecrets(envFiles, cwd, minLength = 8, safeEnvPrefixes = []) {
  const values = new Set();
  const valueToName = new Map();

  for (const envFile of envFiles) {
    const filePath = join(cwd, envFile);
    let content;
    try {
      content = readFileSync(filePath, "utf-8");
    } catch {
      // File doesn't exist, skip
      continue;
    }

    const pairs = parseEnvFile(content);
    for (const { key, value } of pairs) {
      // Skip short values
      if (value.length < minLength) continue;

      // Skip safe prefixes
      const isSafe = safeEnvPrefixes.some((prefix) =>
        key.startsWith(prefix)
      );
      if (isSafe) continue;

      values.add(value);
      valueToName.set(value, key);
    }
  }

  return { values, valueToName };
}

module.exports = { loadSecrets, parseEnvFile };
