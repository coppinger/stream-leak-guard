const { readFileSync } = require("node:fs");
const { join } = require("node:path");

const DEFAULTS = {
  enabled: true,
  envFiles: [".env", ".env.local", ".env.development", ".env.production"],
  sensitiveFiles: [
    ".env",
    ".env.*",
    "credentials.json",
    "service-account.json",
    "*.pem",
    "*.key",
    "id_rsa",
    "id_ed25519",
    ".npmrc",
    ".pypirc",
  ],
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

function loadConfig(cwd) {
  const configPath = join(cwd, ".streamguardrc.json");
  try {
    const raw = readFileSync(configPath, "utf-8");
    const parsed = JSON.parse(raw);
    return { ...DEFAULTS, ...parsed };
  } catch {
    return { ...DEFAULTS };
  }
}

module.exports = { loadConfig, DEFAULTS };
