#!/usr/bin/env node

const { readFileSync, writeFileSync, existsSync, copyFileSync } = require("node:fs");
const { join } = require("node:path");
const { homedir } = require("node:os");

const { handleSessionStart } = require("../src/hooks/session-start");
const { handlePreToolUse } = require("../src/hooks/pre-tool-use");

// ── Hook dispatch ──

function runHook(hookName) {
  let input = "";
  try {
    input = readFileSync(0, "utf-8");
  } catch {
    // No stdin is fine for session-start
  }

  switch (hookName) {
    case "session-start":
      handleSessionStart();
      break;
    case "pre-tool-use": {
      let hookEvent;
      try {
        hookEvent = JSON.parse(input);
      } catch {
        // Can't parse input — fail open
        process.stderr.write("[stream-leak-guard] Warning: Could not parse hook input\n");
        process.exit(0);
      }
      handlePreToolUse(hookEvent);
      break;
    }
    default:
      process.stderr.write(`[stream-leak-guard] Unknown hook: ${hookName}\n`);
      process.exit(1);
  }
}

// ── Settings.json helpers ──

function getSettingsPath() {
  return join(homedir(), ".claude", "settings.json");
}

function readSettings() {
  const settingsPath = getSettingsPath();
  if (!existsSync(settingsPath)) {
    return {};
  }
  try {
    return JSON.parse(readFileSync(settingsPath, "utf-8"));
  } catch {
    return {};
  }
}

function writeSettings(settings) {
  const settingsPath = getSettingsPath();
  const dir = join(homedir(), ".claude");
  if (!existsSync(dir)) {
    require("node:fs").mkdirSync(dir, { recursive: true });
  }
  writeFileSync(settingsPath, JSON.stringify(settings, null, 2) + "\n");
}

function backupSettings() {
  const settingsPath = getSettingsPath();
  if (existsSync(settingsPath)) {
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const backupPath = settingsPath + `.bak-${timestamp}`;
    copyFileSync(settingsPath, backupPath);
    return backupPath;
  }
  return null;
}

// ── Hook definitions ──

const HOOK_ENTRIES = {
  SessionStart: [
    {
      matcher: "",
      hooks: [
        {
          type: "command",
          command: "stream-leak-guard --hook session-start",
          timeout: 5,
        },
      ],
    },
  ],
  PreToolUse: [
    {
      matcher: "Bash|Read|Write|Edit",
      hooks: [
        {
          type: "command",
          command: "stream-leak-guard --hook pre-tool-use",
          timeout: 5,
        },
      ],
    },
  ],
};

/**
 * Remove existing stream-leak-guard entries from hooks.
 */
function removeGuardEntries(hooks) {
  const cleaned = {};
  for (const [event, entries] of Object.entries(hooks)) {
    const filtered = entries.filter((entry) => {
      if (!entry.hooks) return true;
      return !entry.hooks.some(
        (h) => h.command && h.command.includes("stream-leak-guard")
      );
    });
    if (filtered.length > 0) {
      cleaned[event] = filtered;
    }
  }
  return cleaned;
}

/**
 * Check if stream-leak-guard hooks are present.
 */
function hasGuardHooks(settings) {
  const hooks = settings.hooks || {};
  const hasSession = (hooks.SessionStart || []).some((entry) =>
    (entry.hooks || []).some(
      (h) => h.command && h.command.includes("stream-leak-guard")
    )
  );
  const hasPreTool = (hooks.PreToolUse || []).some((entry) =>
    (entry.hooks || []).some(
      (h) => h.command && h.command.includes("stream-leak-guard")
    )
  );
  return { hasSession, hasPreTool, both: hasSession && hasPreTool };
}

// ── CLI Commands ──

function cmdInit() {
  const backupPath = backupSettings();
  if (backupPath) {
    console.log(`Backed up settings to: ${backupPath}`);
  }

  const settings = readSettings();

  // Remove existing entries first (idempotent)
  if (settings.hooks) {
    settings.hooks = removeGuardEntries(settings.hooks);
  } else {
    settings.hooks = {};
  }

  // Add hook entries
  for (const [event, entries] of Object.entries(HOOK_ENTRIES)) {
    if (!settings.hooks[event]) {
      settings.hooks[event] = [];
    }
    settings.hooks[event].push(...entries);
  }

  writeSettings(settings);
  console.log("stream-leak-guard hooks installed in ~/.claude/settings.json");

  // Create example config if it doesn't exist
  const examplePath = join(process.cwd(), ".streamguardrc.json.example");
  if (!existsSync(examplePath)) {
    const example = {
      enabled: true,
      envFiles: [".env", ".env.local", ".env.development", ".env.production"],
      sensitiveFiles: [".env", ".env.*", "credentials.json", "*.pem", "*.key"],
      customPatterns: [],
      allowedCommands: [],
      minSecretLength: 8,
      safeEnvPrefixes: [
        "PUBLIC_",
        "NEXT_PUBLIC_",
        "VITE_",
        "REACT_APP_",
        "EXPO_PUBLIC_",
      ],
      verbose: false,
    };
    writeFileSync(examplePath, JSON.stringify(example, null, 2) + "\n");
    console.log("Created .streamguardrc.json.example in current directory");
  }

  console.log("\nSetup complete! Start a new Claude Code session to activate.");
}

function cmdStatus() {
  const settings = readSettings();
  const { hasSession, hasPreTool, both } = hasGuardHooks(settings);

  console.log("stream-leak-guard status:");
  console.log(`  SessionStart hook: ${hasSession ? "installed" : "not found"}`);
  console.log(`  PreToolUse hook:   ${hasPreTool ? "installed" : "not found"}`);

  if (both) {
    console.log("\nAll hooks are configured. Protection is active.");
  } else if (hasSession || hasPreTool) {
    console.log("\nWarning: Some hooks are missing. Run `stream-leak-guard init` to fix.");
  } else {
    console.log("\nNo hooks found. Run `stream-leak-guard init` to set up.");
  }

  // Check for config file
  const configPath = join(process.cwd(), ".streamguardrc.json");
  if (existsSync(configPath)) {
    console.log(`\nConfig file found: ${configPath}`);
  } else {
    console.log("\nNo .streamguardrc.json found (using defaults).");
  }
}

function cmdDisable() {
  const settings = readSettings();

  if (!settings.hooks) {
    console.log("No hooks found in settings.");
    return;
  }

  const { both } = hasGuardHooks(settings);
  if (!both && !hasGuardHooks(settings).hasSession && !hasGuardHooks(settings).hasPreTool) {
    console.log("stream-leak-guard hooks are not installed.");
    return;
  }

  const backupPath = backupSettings();
  if (backupPath) {
    console.log(`Backed up settings to: ${backupPath}`);
  }

  settings.hooks = removeGuardEntries(settings.hooks);

  // Clean up empty hooks object
  if (Object.keys(settings.hooks).length === 0) {
    delete settings.hooks;
  }

  writeSettings(settings);
  console.log("stream-leak-guard hooks removed from ~/.claude/settings.json");
}

function printUsage() {
  console.log(`stream-leak-guard — Protect secrets while streaming with Claude Code

Usage:
  stream-leak-guard init       Set up hooks in ~/.claude/settings.json
  stream-leak-guard status     Check if hooks are configured
  stream-leak-guard disable    Remove hooks from settings

Hook mode (called by Claude Code):
  stream-leak-guard --hook session-start
  stream-leak-guard --hook pre-tool-use`);
}

// ── Main ──

function main() {
  const args = process.argv.slice(2);

  if (args[0] === "--hook" && args[1]) {
    runHook(args[1]);
    return;
  }

  switch (args[0]) {
    case "init":
      cmdInit();
      break;
    case "status":
      cmdStatus();
      break;
    case "disable":
      cmdDisable();
      break;
    case "--help":
    case "-h":
      printUsage();
      break;
    default:
      printUsage();
      process.exit(args.length === 0 ? 0 : 1);
  }
}

main();
