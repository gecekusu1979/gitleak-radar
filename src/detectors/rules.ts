import { DetectionRule } from "../types/index.js";

export const DETECTION_RULES: DetectionRule[] = [
  {
    id: "aws-access-key",
    name: "AWS Access Key",
    description: "Identifies standard AWS Access Key IDs (AKIA...)",
    severity: "critical",
    pattern: /\b(AKIA[0-9A-Z]{16})\b/g,
    keywords: ["akia"]
  },
  {
    id: "aws-secret-key",
    name: "AWS Secret Access Key",
    description: "Identifies high-entropy AWS Secret Access Key patterns",
    severity: "critical",
    pattern: /(?:aws[-_]?secret[-_]?access[-_]?key|aws[-_]?secret[-_]?key|secret[-_]?access[-_]?key|secret[-_]?key)\s*[:=]\s*["']?([A-Za-z0-9\/+=]{40})["']?/gi,
    keywords: ["aws", "secret", "key"]
  },
  {
    id: "github-pat",
    name: "GitHub Personal Access Token",
    description: "Identifies classic and fine-grained GitHub access tokens",
    severity: "critical",
    pattern: /\b(gh[opusr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b/g,
    keywords: ["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"]
  },
  {
    id: "gitlab-pat",
    name: "GitLab Personal Access Token",
    description: "Identifies GitLab personal and project access tokens",
    severity: "critical",
    pattern: /\b(glpat-[0-9a-zA-Z\-_]{20,32})\b/g,
    keywords: ["glpat-"]
  },
  {
    id: "stripe-api-key",
    name: "Stripe API Key",
    description: "Identifies live Stripe standard and restricted secret keys",
    severity: "critical",
    pattern: /\b((?:sk|rk)_live_[0-9a-zA-Z]{24,34})\b/g,
    keywords: ["sk_live_", "rk_live_"]
  },
  {
    id: "openai-api-key",
    name: "OpenAI API Key",
    description: "Identifies legacy and project-scoped OpenAI secret keys",
    severity: "critical",
    pattern: /\b(sk-(?:proj-)?[A-Za-z0-9_-]{48,64})\b/g,
    keywords: ["sk-"]
  },
  {
    id: "slack-webhook",
    name: "Slack Webhook URL",
    description: "Identifies standard Slack incoming webhook URLs",
    severity: "high",
    pattern: /(https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8,}\/B[a-zA-Z0-9_]{8,}\/[a-zA-Z0-9_]{24})/g,
    keywords: ["hooks.slack.com/services"]
  },
  {
    id: "gcp-service-account",
    name: "GCP Service Account Private Key",
    description: "Identifies Google Cloud Platform service account private keys",
    severity: "critical",
    pattern: /("type":\s*"service_account"[\s\S]*?"private_key":\s*"-----BEGIN PRIVATE KEY-----\n[A-Za-z0-9\/+=\n]+?\n-----END PRIVATE KEY-----\n")/g,
    keywords: ["service_account", "private_key"]
  },
  {
    id: "gcp-api-key",
    name: "GCP API Key",
    description: "Identifies Google Cloud API keys",
    severity: "high",
    pattern: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
    keywords: ["AIza"]
  },
  {
    id: "azure-ad-client-secret",
    name: "Azure AD Client Secret",
    description: "Identifies Azure App Service / AD client secrets",
    severity: "critical",
    pattern: /(?:client_secret|clientsecret|tenant_id)\s*[:=]\s*["']?([a-zA-Z0-9~.-_]{30,45})["']?/ig,
    keywords: ["client_secret", "clientsecret", "tenant_id"]
  },
  {
    id: "heroku-api-key",
    name: "Heroku API Key",
    description: "Identifies Heroku authorization API keys",
    severity: "high",
    pattern: /(?:heroku[-_]?api[-_]?key|heroku[-_]?key)\s*[:=]\s*["']?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})["']?/ig,
    keywords: ["heroku"]
  },
  {
    id: "firebase-url",
    name: "Firebase Realtime DB URL",
    description: "Identifies Firebase database domain mappings",
    severity: "medium",
    pattern: /(https:\/\/[a-z0-9-]+\.firebaseio\.com)/g,
    keywords: ["firebaseio.com"]
  },
  {
    id: "npm-access-token",
    name: "NPM Access Token",
    description: "Identifies NPM access tokens for package registry",
    severity: "high",
    pattern: /\b(npm_[A-Za-z0-9]{36})\b/g,
    keywords: ["npm_"]
  },
  {
    id: "azure-storage-key",
    name: "Azure Storage Account Key",
    description: "Identifies Azure Storage access keys and connection string keys",
    severity: "critical",
    pattern: /(?:AccountKey|SharedAccessKey)\s*[:=]\s*["']?([A-Za-z0-9+/=]{86,88})["']?/gi,
    keywords: ["accountkey", "sharedaccesskey"]
  },
  {
    id: "jwt",
    name: "JSON Web Token (JWT)",
    description: "Identifies hardcoded base64-encoded JWT signatures",
    severity: "high",
    requiresEntropy: true,
    minEntropy: 3.0,
    pattern: /\b(ey[A-Za-z0-9-_=]+\.ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+)\b/g,
    keywords: ["ey"]
  },
  {
    id: "private-key",
    name: "Private Key",
    description: "Identifies RSA, EC, OPENSSH or standard Private Keys",
    severity: "critical",
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
    keywords: ["begin", "private key"]
  },
  {
    id: "slack-token",
    name: "Slack Token",
    description: "Identifies Slack user/bot OAuth access tokens",
    severity: "high",
    pattern: /\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*)\b/g,
    keywords: ["xox"]
  },
  {
    id: "google-api-key",
    name: "Google API Key",
    description: "Identifies Google Cloud and service API keys",
    severity: "high",
    pattern: /\b(AIza[0-9A-Za-z_-]{35})\b/g,
    keywords: ["aiza"]
  },
  {
    id: "db-connection-string",
    name: "Database Connection String",
    description: "Identifies embedded user credentials in connection URIs",
    severity: "high",
    pattern: /\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql):\/\/[^\s:]+:([^\s@]+)@[^\s]+(?::\d+)?\b/gi,
    keywords: ["mongodb", "postgres", "mysql"]
  },
  {
    id: "twilio-api-key",
    name: "Twilio API Key",
    description: "Identifies Twilio API Key SIDs",
    severity: "critical",
    pattern: /\b(SK[0-9a-fA-F]{32})\b/g,
    keywords: ["sk"]
  },
  {
    id: "sendgrid-api-key",
    name: "SendGrid API Key",
    description: "Identifies SendGrid API keys used for transactional email sending",
    severity: "critical",
    pattern: /\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b/g,
    keywords: ["sg."]
  },
  {
    id: "npm-token",
    name: "npm Access Token",
    description: "Identifies npm registry publish/read tokens (supply-chain risk)",
    severity: "critical",
    pattern: /\b(npm_[A-Za-z0-9]{36})\b/g,
    keywords: ["npm_"]
  },
  {
    id: "pypi-token",
    name: "PyPI API Token",
    description: "Identifies PyPI upload tokens (supply-chain risk)",
    severity: "critical",
    pattern: /\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,})\b/g,
    keywords: ["pypi-ageichlwas"]
  },
  {
    id: "digitalocean-token",
    name: "DigitalOcean Personal Access Token",
    description: "Identifies DigitalOcean API personal access tokens",
    severity: "critical",
    pattern: /\b(dop_v1_[a-f0-9]{64})\b/g,
    keywords: ["dop_v1_"]
  },
  {
    id: "discord-webhook",
    name: "Discord Webhook",
    description: "Identifies published Discord webhook URLs",
    severity: "high",
    pattern: /(https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+)/g,
    keywords: ["discord.com/api/webhooks", "discordapp.com/api/webhooks"]
  },
  {
    id: "generic-api-key",
    name: "Generic API Key",
    description: "Identifies assignments of high-entropy strings to api_key variables",
    severity: "medium",
    requiresEntropy: true,
    minEntropy: 3.0,
    pattern: /(?:api[-_]?key|secret|api[-_]?token)\s*[:=]\s*["']?([A-Za-z0-9\-_]{20,64})["']?/gi,
    keywords: ["api", "secret", "token"]
  },
  {
    id: "generic-bearer-token",
    name: "Generic Bearer Token",
    description: "Identifies hardcoded Bearer authorization tokens",
    severity: "high",
    requiresEntropy: true,
    minEntropy: 3.0,
    pattern: /(?:bearer)\s+([A-Za-z0-9\-._~+/]{20,}=*)/gi,
    keywords: ["bearer"]
  },
  {
    id: "generic-password",
    name: "Generic Password Assignment",
    description: "Identifies static password variable definitions with literal values",
    severity: "medium",
    minEntropy: 3.0,
    // Expression değerleri negatif lookahead ile dışla:
    //   process.env.X  → değer "process" ile başlar, "." içerir ama identifier+.identifier örüntüsü
    //   fn()           → değer "(" ile sonlanmadan önce gelir
    //   ${template}    → değer "$" ile başlar
    // Yakaladığımız: quoted literal VEYA tırnaksız basit token (.env formatı)
    pattern: /(?:password|passwd|pwd)\s*[:=]\s*(?!(?:process\.|getenv\b|\$\{|[a-zA-Z_]\w*\())(?:["']([^"'\\]{8,64})["']|([^"'\s#$()\[\]{};]{8,64})(?=[\s#;]|$))/gi,
    keywords: ["password", "passwd", "pwd"]
  }
];
