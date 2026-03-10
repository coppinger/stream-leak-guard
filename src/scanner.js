const { SECRET_PATTERNS } = require("./patterns");

/**
 * Check if text is in an assignment context (KEY=value, "key": "value", etc.)
 */
function isAssignmentContext(text, matchIndex) {
  // Look backward from the match for = or : preceded by a key-like identifier
  const before = text.slice(Math.max(0, matchIndex - 100), matchIndex);
  return /[=:]\s*['"]?\s*$/.test(before);
}

/**
 * Scan text for secrets using exact values and regex patterns.
 * Returns { found: boolean, matches: [{ type, name, location }] }
 */
function scanForSecrets(text, secretValues, patterns = SECRET_PATTERNS, valueToName = null, customPatterns = []) {
  const matches = [];

  if (!text) return { found: false, matches };

  // 1. Exact value matching
  if (secretValues) {
    for (const secret of secretValues) {
      if (text.includes(secret)) {
        const name = valueToName ? valueToName.get(secret) : "unknown";
        matches.push({
          type: "exact",
          name: `env:${name}`,
          location: "exact value match",
        });
      }
    }
  }

  // 2. Pattern matching
  for (const pattern of patterns) {
    const match = pattern.regex.exec(text);
    if (match) {
      if (pattern.tooGeneric && !isAssignmentContext(text, match.index)) {
        continue;
      }
      matches.push({
        type: "pattern",
        name: pattern.name,
        location: `pattern match`,
      });
    }
  }

  // 3. Custom patterns from config
  for (const custom of customPatterns) {
    try {
      const re = new RegExp(custom.regex || custom);
      if (re.test(text)) {
        matches.push({
          type: "custom",
          name: custom.name || "Custom pattern",
          location: "custom pattern match",
        });
      }
    } catch {
      // Invalid regex, skip
    }
  }

  return { found: matches.length > 0, matches };
}

/**
 * Scrub secret values from a string before outputting it.
 */
function sanitizeForOutput(message, secretValues) {
  if (!secretValues || !message) return message;
  let result = message;
  for (const secret of secretValues) {
    if (result.includes(secret)) {
      result = result.split(secret).join("[REDACTED]");
    }
  }
  return result;
}

module.exports = { scanForSecrets, sanitizeForOutput, isAssignmentContext };
