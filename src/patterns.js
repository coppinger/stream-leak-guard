/**
 * Regex patterns for known secret formats.
 * Each entry: { name, regex, description, tooGeneric? }
 * Patterns marked tooGeneric only match in assignment contexts (KEY=value, "key": "value").
 */

const SECRET_PATTERNS = [
  // AWS
  {
    name: "AWS Access Key ID",
    regex: /AKIA[0-9A-Z]{16}/,
    description: "AWS access key ID",
  },
  {
    name: "AWS Secret Access Key",
    regex: /(?:aws_secret_access_key|aws_secret)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/i,
    description: "AWS secret access key in assignment context",
  },

  // GitHub
  {
    name: "GitHub Personal Access Token",
    regex: /ghp_[A-Za-z0-9]{36}/,
    description: "GitHub personal access token",
  },
  {
    name: "GitHub Fine-grained PAT",
    regex: /github_pat_[A-Za-z0-9_]{22,}/,
    description: "GitHub fine-grained personal access token",
  },
  {
    name: "GitHub OAuth Token",
    regex: /gho_[A-Za-z0-9]{36}/,
    description: "GitHub OAuth access token",
  },
  {
    name: "GitHub User-to-Server Token",
    regex: /ghu_[A-Za-z0-9]{36}/,
    description: "GitHub user-to-server token",
  },
  {
    name: "GitHub Server-to-Server Token",
    regex: /ghs_[A-Za-z0-9]{36}/,
    description: "GitHub server-to-server token",
  },
  {
    name: "GitHub Refresh Token",
    regex: /ghr_[A-Za-z0-9]{36}/,
    description: "GitHub refresh token",
  },

  // AI Providers
  {
    name: "Anthropic API Key",
    regex: /sk-ant-[A-Za-z0-9_-]{20,}/,
    description: "Anthropic API key",
  },
  {
    name: "OpenAI API Key (project)",
    regex: /sk-proj-[A-Za-z0-9_-]{20,}/,
    description: "OpenAI project API key",
  },
  {
    name: "OpenAI API Key (legacy)",
    regex: /sk-[A-Za-z0-9]{48,}/,
    description: "OpenAI legacy API key",
  },

  // Slack
  {
    name: "Slack Bot Token",
    regex: /xoxb-[0-9]{10,}-[0-9A-Za-z-]+/,
    description: "Slack bot token",
  },
  {
    name: "Slack User Token",
    regex: /xoxp-[0-9]{10,}-[0-9A-Za-z-]+/,
    description: "Slack user token",
  },
  {
    name: "Slack Webhook URL",
    regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/,
    description: "Slack incoming webhook URL",
  },

  // Stripe
  {
    name: "Stripe Secret Key",
    regex: /sk_live_[A-Za-z0-9]{24,}/,
    description: "Stripe live secret key",
  },
  {
    name: "Stripe Restricted Key",
    regex: /rk_live_[A-Za-z0-9]{24,}/,
    description: "Stripe live restricted key",
  },

  // Google
  {
    name: "Google API Key",
    regex: /AIza[0-9A-Za-z_-]{35}/,
    description: "Google API key",
  },

  // npm
  {
    name: "npm Token",
    regex: /npm_[a-zA-Z0-9]{36}/,
    description: "npm access token",
  },

  // Private Keys
  {
    name: "Private Key",
    regex: /-----BEGIN\s(?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/,
    description: "Private key header",
  },

  // Database URLs with credentials
  {
    name: "Database URL with Password",
    regex: /(?:postgres|mysql|mongodb|redis):\/\/[^:\s]+:[^@\s]+@[^\s]+/,
    description: "Database connection string with embedded password",
  },

  // Discord
  {
    name: "Discord Bot Token",
    regex: /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}/,
    description: "Discord bot token",
  },

  // Twilio
  {
    name: "Twilio API Key",
    regex: /SK[0-9a-fA-F]{32}/,
    description: "Twilio API key",
  },

  // SendGrid
  {
    name: "SendGrid API Key",
    regex: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/,
    description: "SendGrid API key",
  },

  // Vercel
  {
    name: "Vercel Token",
    regex: /vercel_[A-Za-z0-9_-]{24,}/i,
    description: "Vercel access token",
  },

  // Supabase
  {
    name: "Supabase Service Role Key",
    regex: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{20,}/,
    description: "Supabase service role key (JWT format)",
  },

  // JWT (generic, too generic — only match in assignment context)
  {
    name: "JSON Web Token",
    regex: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/,
    description: "JSON Web Token (3-part base64)",
    tooGeneric: true,
  },

  // Generic high-entropy secrets in assignment context
  {
    name: "Generic Secret Assignment",
    regex: /(?:secret|password|token|api_key|apikey|auth|credential)[\s]*[:=][\s]*['"]([^'"]{8,})['"]/i,
    description: "Generic secret in assignment context",
    tooGeneric: true,
  },
];

module.exports = { SECRET_PATTERNS };
