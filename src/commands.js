/**
 * Dangerous command patterns and analysis for Bash tool inputs.
 */

/**
 * Common secret-like env var names used with echo/printf.
 */
const SECRET_VAR_NAMES = [
  "SECRET", "PASSWORD", "PASSWD", "TOKEN", "API_KEY", "APIKEY",
  "AUTH", "CREDENTIAL", "PRIVATE_KEY", "ACCESS_KEY", "SECRET_KEY",
  "DATABASE_URL", "DB_PASSWORD", "DB_PASS", "ENCRYPTION_KEY",
  "JWT_SECRET", "SESSION_SECRET", "SIGNING_KEY",
];

/**
 * Split a compound command into individual parts.
 * Handles &&, ||, ;, |, and $(...) subshells.
 */
function splitCommandParts(command) {
  const parts = [];
  // Split on &&, ||, ;, | (but not ||)
  // Simple split — good enough for detection
  const segments = command.split(/\s*(?:&&|\|\||[;|])\s*/);
  for (const segment of segments) {
    const trimmed = segment.trim();
    if (trimmed) parts.push(trimmed);
  }

  // Also extract subshell contents: $(...)
  const subshellRe = /\$\(([^)]+)\)/g;
  let match;
  while ((match = subshellRe.exec(command)) !== null) {
    parts.push(match[1].trim());
  }

  // Backtick subshells
  const backtickRe = /`([^`]+)`/g;
  while ((match = backtickRe.exec(command)) !== null) {
    parts.push(match[1].trim());
  }

  return parts;
}

/**
 * Check if a single command part is dangerous.
 */
function checkSingleCommand(cmd) {
  const trimmed = cmd.trim();
  const parts = trimmed.split(/\s+/);
  const base = parts[0];

  // env (no args) — dumps all env vars
  if (base === "env" && parts.length === 1) {
    return {
      blocked: true,
      reason: "The `env` command without arguments dumps all environment variables",
      suggestion: "Use specific variable references like $VAR_NAME instead",
    };
  }

  // printenv (no args) — dumps all env vars
  if (base === "printenv" && parts.length === 1) {
    return {
      blocked: true,
      reason: "The `printenv` command without arguments dumps all environment variables",
      suggestion: "Use `printenv VAR_NAME` for a specific variable instead",
    };
  }

  // export -p — lists all exported vars
  if (base === "export" && parts.includes("-p")) {
    return {
      blocked: true,
      reason: "`export -p` lists all exported environment variables",
      suggestion: "Reference specific variables like $VAR_NAME instead",
    };
  }

  // set (no args or no flags) — dumps all shell vars
  if (base === "set" && parts.length === 1) {
    return {
      blocked: true,
      reason: "The `set` command without arguments dumps all shell variables",
      suggestion: "Use `set -e` or other flags, or reference specific variables",
    };
  }

  // declare -p (no specific var) — dumps all vars
  if (base === "declare" && parts.includes("-p") && parts.length === 2) {
    return {
      blocked: true,
      reason: "`declare -p` without a variable name dumps all declared variables",
      suggestion: "Use `declare -p SPECIFIC_VAR` instead",
    };
  }

  // cat/head/tail/less/more on .env files
  if (["cat", "head", "tail", "less", "more", "bat"].includes(base)) {
    for (let i = 1; i < parts.length; i++) {
      const arg = parts[i];
      if (/^\.env/.test(arg) || /\/\.env/.test(arg)) {
        return {
          blocked: true,
          reason: `Reading .env file (${arg}) would expose secret values on screen`,
          suggestion: "Use `grep -c '' .env` to count lines, or reference specific vars by name",
        };
      }
    }
  }

  // source .env / . .env
  if (
    (base === "source" || base === ".") &&
    parts[1] &&
    (/^\.env/.test(parts[1]) || /\/\.env/.test(parts[1]))
  ) {
    return {
      blocked: true,
      reason: `Sourcing ${parts[1]} could expose secrets through shell expansion`,
      suggestion: "Reference specific variables directly instead of sourcing the env file",
    };
  }

  // echo/printf with secret-looking variable names
  if (["echo", "printf"].includes(base)) {
    const rest = trimmed.slice(base.length);
    for (const varName of SECRET_VAR_NAMES) {
      const pattern = new RegExp(`\\$\\{?${varName}\\}?|\\$\\{?[A-Z_]*${varName}[A-Z_]*\\}?`, "i");
      if (pattern.test(rest)) {
        return {
          blocked: true,
          reason: `Echoing $${varName} would print a secret value to the terminal`,
          suggestion: `Reference the variable by name without echoing its value`,
        };
      }
    }
  }

  return null;
}

/**
 * Analyze a command for dangerous operations.
 * Returns { blocked: boolean, reason?: string, suggestion?: string }
 */
function analyzeCommand(command, allowedCommands = []) {
  if (!command || !command.trim()) {
    return { blocked: false };
  }

  // Check allowlist first
  const trimmed = command.trim();
  for (const allowed of allowedCommands) {
    if (trimmed === allowed || trimmed.startsWith(allowed + " ")) {
      return { blocked: false };
    }
  }

  // Check all parts of compound commands
  const parts = splitCommandParts(command);
  for (const part of parts) {
    const result = checkSingleCommand(part);
    if (result) return result;
  }

  return { blocked: false };
}

module.exports = { analyzeCommand, splitCommandParts, SECRET_VAR_NAMES };
