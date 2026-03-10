const { loadConfig } = require("../config");
const { loadSecrets } = require("../env-loader");
const { scanForSecrets, sanitizeForOutput } = require("../scanner");
const { analyzeCommand } = require("../commands");

/**
 * Check if a file path matches any sensitive file pattern.
 */
function matchesSensitiveFile(filePath, sensitiveFiles) {
  if (!filePath) return false;
  const basename = filePath.split("/").pop();

  for (const pattern of sensitiveFiles) {
    // Exact match
    if (basename === pattern) return true;

    // Glob-style: .env.* matches .env.local, .env.production, etc.
    if (pattern.includes("*")) {
      const re = new RegExp(
        "^" + pattern.replace(/\./g, "\\.").replace(/\*/g, ".*") + "$"
      );
      if (re.test(basename)) return true;
    }

    // Also check if the full path ends with the pattern
    if (filePath.endsWith("/" + pattern) || filePath === pattern) return true;
  }
  return false;
}

function deny(reason) {
  const output = {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: `[stream-leak-guard] Blocked: ${reason}`,
    },
  };
  process.stdout.write(JSON.stringify(output));
  process.exit(0);
}

function allow() {
  process.exit(0);
}

function handlePreToolUse(hookEvent) {
  const cwd = process.cwd();
  const config = loadConfig(cwd);

  if (!config.enabled) {
    allow();
    return;
  }

  const { values, valueToName } = loadSecrets(
    config.envFiles,
    cwd,
    config.minSecretLength,
    config.safeEnvPrefixes
  );

  const toolName = hookEvent.tool_name;
  const toolInput = hookEvent.tool_input || {};

  switch (toolName) {
    case "Bash": {
      const command = toolInput.command || "";

      // Check for dangerous commands
      const cmdResult = analyzeCommand(command, config.allowedCommands);
      if (cmdResult.blocked) {
        deny(`${cmdResult.reason}. ${cmdResult.suggestion}`);
        return;
      }

      // Scan command text for secret values
      const scanResult = scanForSecrets(command, values, undefined, valueToName, config.customPatterns);
      if (scanResult.found) {
        const names = scanResult.matches.map((m) => m.name).join(", ");
        deny(
          sanitizeForOutput(
            `Command contains secret values (${names}). Use variable references ($VAR_NAME) instead of literal values.`,
            values
          )
        );
        return;
      }
      break;
    }

    case "Read": {
      const filePath = toolInput.file_path || "";
      if (matchesSensitiveFile(filePath, config.sensitiveFiles)) {
        deny(
          `Reading ${filePath.split("/").pop()} would expose secret values on screen. Reference secrets by variable name instead.`
        );
        return;
      }
      break;
    }

    case "Write": {
      const content = toolInput.content || "";
      const scanResult = scanForSecrets(content, values, undefined, valueToName, config.customPatterns);
      if (scanResult.found) {
        const names = scanResult.matches.map((m) => m.name).join(", ");
        deny(
          sanitizeForOutput(
            `File content contains secret values (${names}). Use placeholder values or environment variable references instead.`,
            values
          )
        );
        return;
      }
      break;
    }

    case "Edit": {
      const newString = toolInput.new_string || "";
      const scanResult = scanForSecrets(newString, values, undefined, valueToName, config.customPatterns);
      if (scanResult.found) {
        const names = scanResult.matches.map((m) => m.name).join(", ");
        deny(
          sanitizeForOutput(
            `Edit contains secret values (${names}). Use placeholder values or environment variable references instead.`,
            values
          )
        );
        return;
      }
      break;
    }
  }

  allow();
}

module.exports = { handlePreToolUse, matchesSensitiveFile };
