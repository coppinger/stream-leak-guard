# stream-leak-guard

Protect secrets from leaking on stream when using Claude Code on Twitch/YouTube.

Uses [Claude Code hooks](https://docs.anthropic.com/en/docs/claude-code/hooks) to intercept tool calls and block secret exposure before it reaches the screen.

## Quick Start

```bash
# Install globally
npm install -g stream-leak-guard

# Set up hooks in Claude Code
stream-leak-guard init

# Start streaming safely
claude
```

## How It Works

Three Claude Code hooks work together:

1. **SessionStart** — Injects safety instructions into Claude's context so it avoids outputting secrets in its text responses
2. **PreToolUse** (Bash, Read, Write, Edit) — Blocks dangerous commands and scans for secret values before any tool executes
3. **PostToolUse** (Bash, Read, Write, Edit) — Scans tool output after execution and redacts any secret values or patterns before they reach the conversation context

### What Gets Blocked (PreToolUse)

**Dangerous commands:**
- `env`, `printenv` (without arguments) — dump all environment variables
- `export -p`, `set`, `declare -p` — list all shell/exported variables
- `cat .env`, `head .env.local`, etc. — read env files directly
- `source .env`, `. .env` — source env files
- `echo $SECRET_KEY`, `echo $API_KEY` — print known secret variable names
- `grep`/`rg`/`ag`/`egrep`/`fgrep` targeting `.env` files
- `awk`/`sed`/`cut`/`sort`/`tr`/`wc`/`tee`/`xargs`/`strings` targeting `.env` files
- Inline code execution accessing `.env` files (`node -e`, `python -c`, `ruby -e`)
- Any command with `.env` file arguments (`cp .env /tmp/`, `diff .env .env.bak`, etc.)

**Secret values detected by:**
- **Exact matching** — Loads actual values from `.env` files and matches against command/content text
- **Pattern matching** — Regex patterns for known secret formats (AWS keys, GitHub tokens, API keys, etc.)

**Sensitive file reads:**
- `.env`, `.env.*` files
- `credentials.json`, `*.pem`, `*.key`, `id_rsa`, `id_ed25519`
- `.npmrc`, `.pypirc`

### What Gets Redacted (PostToolUse)

If a secret value or known pattern slips through in tool output (e.g. a command prints a database URL, or a file read includes an API key), the PostToolUse hook replaces it with `[REDACTED:VAR_NAME]` before the output is shown. This covers:

- **Exact value matching** — Any value loaded from `.env` files
- **Pattern matching** — Known secret formats (AWS keys, GitHub tokens, private keys, database URLs, etc.)
- **Custom patterns** — Any additional patterns defined in your `.streamguardrc.json`

Large outputs (>1MB) skip regex pattern scanning for performance but still perform exact value redaction.

### What's Allowed

Everything else. Normal commands (`npm test`, `ls`, `git status`, `node app.js`) flow through unimpeded. The guard only blocks truly dangerous operations and commands containing literal secret values.

## Configuration

Create a `.streamguardrc.json` in your project root to customize behavior:

```json
{
  "enabled": true,
  "envFiles": [".env", ".env.local", ".env.development", ".env.production"],
  "sensitiveFiles": [".env", ".env.*", "credentials.json", "*.pem", "*.key"],
  "customPatterns": [],
  "allowedCommands": [],
  "minSecretLength": 8,
  "safeEnvPrefixes": ["PUBLIC_", "NEXT_PUBLIC_", "VITE_", "REACT_APP_", "EXPO_PUBLIC_"],
  "verbose": false
}
```

Run `stream-leak-guard init` to create an example config file.

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | `true` | Enable/disable the guard |
| `envFiles` | `[".env", ".env.local", ...]` | Files to load secret values from |
| `sensitiveFiles` | `[".env", ".env.*", ...]` | File patterns to block reading |
| `customPatterns` | `[]` | Additional regex patterns `[{ regex, name }]` |
| `allowedCommands` | `[]` | Commands to always allow (bypass blocking) |
| `minSecretLength` | `8` | Minimum value length to treat as a secret |
| `safeEnvPrefixes` | `["PUBLIC_", ...]` | Env var prefixes that are safe (skipped during scanning) |
| `verbose` | `false` | Enable verbose logging to stderr |

## Secret Patterns Detected

- AWS Access Keys (`AKIA...`)
- GitHub Tokens (`ghp_`, `github_pat_`, `gho_`, `ghu_`, `ghs_`, `ghr_`)
- Anthropic API Keys (`sk-ant-`)
- OpenAI API Keys (`sk-proj-`, `sk-...`)
- Slack Tokens (`xoxb-`, `xoxp-`) and Webhook URLs
- Stripe Keys (`sk_live_`, `rk_live_`)
- Google API Keys (`AIza...`)
- npm Tokens (`npm_...`)
- Private Keys (`-----BEGIN ... PRIVATE KEY-----`)
- Database URLs with passwords (`postgres://user:pass@host`)
- Discord Bot Tokens
- Twilio API Keys (`SK...`)
- SendGrid API Keys (`SG....`)
- Vercel Tokens
- Supabase Service Role Keys
- JWTs (in assignment context)

## CLI Commands

```bash
stream-leak-guard init      # Set up hooks in ~/.claude/settings.json
stream-leak-guard status    # Check if hooks are configured
stream-leak-guard disable   # Remove hooks from settings
```

## Design Principles

- **Zero dependencies** — No supply chain risk. Uses only Node.js built-ins.
- **Fail-open** — If the guard errors, development continues (exit 1 is non-blocking).
- **Value-to-name mapping** — Error messages say "Found DATABASE_URL" not the actual value.
- **Safe env prefixes** — Framework-designated public values (`NEXT_PUBLIC_`, `VITE_`, etc.) are skipped.
- **Bun-first, Node-compatible** — `#!/usr/bin/env node` shebang works everywhere. Bun users get faster hook startup.

## Development

```bash
# Run tests
bun test
```

## License

MIT
