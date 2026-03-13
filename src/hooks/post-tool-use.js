const { loadConfig } = require("../config");
const { loadSecrets } = require("../env-loader");
const { redactSecrets } = require("../scanner");
const { SECRET_PATTERNS } = require("../patterns");

/**
 * Extract scannable text from tool output based on tool type.
 */
function extractOutputText(toolName, toolOutput) {
  if (!toolOutput) return "";

  switch (toolName) {
    case "Bash": {
      const parts = [];
      if (toolOutput.stdout) parts.push(toolOutput.stdout);
      if (toolOutput.stderr) parts.push(toolOutput.stderr);
      return parts.join("\n");
    }
    case "Read":
      return typeof toolOutput === "string"
        ? toolOutput
        : toolOutput.content || "";
    default:
      return typeof toolOutput === "string"
        ? toolOutput
        : JSON.stringify(toolOutput);
  }
}

/**
 * PostToolUse hook handler — scans tool output for secrets and redacts them.
 * Fail-open: any error results in exit 0 with no modification.
 */
function handlePostToolUse(hookEvent) {
  try {
    const cwd = process.cwd();
    const config = loadConfig(cwd);

    if (!config.enabled) {
      process.exit(0);
      return;
    }

    const { values, valueToName } = loadSecrets(
      config.envFiles,
      cwd,
      config.minSecretLength,
      config.safeEnvPrefixes
    );

    const toolName = hookEvent.tool_name;
    const toolOutput = hookEvent.tool_output;
    const outputText = extractOutputText(toolName, toolOutput);

    if (!outputText) {
      process.exit(0);
      return;
    }

    const { redacted, redactionCount } = redactSecrets(
      outputText,
      values,
      valueToName,
      SECRET_PATTERNS,
      config.customPatterns
    );

    if (redactionCount > 0) {
      const output = {
        hookSpecificOutput: {
          hookEventName: "PostToolUse",
          modifiedToolResult: redacted,
        },
      };
      process.stdout.write(JSON.stringify(output));
    }

    process.exit(0);
  } catch {
    // Fail-open: never block on error
    process.exit(0);
  }
}

module.exports = { handlePostToolUse, extractOutputText };
