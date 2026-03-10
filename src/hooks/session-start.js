const { loadConfig } = require("../config");

const SAFETY_CONTEXT =
  "STREAMING SAFETY MODE ACTIVE: You are being used while the developer is live streaming. " +
  "NEVER output secret values, API keys, tokens, passwords, or credentials in your text responses. " +
  "Reference env vars by name ($API_KEY) not by value. Use [REDACTED] as placeholder. " +
  "When reading files that may contain secrets, summarize the structure without showing values.";

function handleSessionStart() {
  const cwd = process.cwd();
  const config = loadConfig(cwd);

  if (!config.enabled) {
    process.exit(0);
    return;
  }

  const output = {
    hookSpecificOutput: {
      hookEventName: "SessionStart",
      additionalContext: SAFETY_CONTEXT,
    },
  };

  process.stdout.write(JSON.stringify(output));
  process.exit(0);
}

module.exports = { handleSessionStart, SAFETY_CONTEXT };
