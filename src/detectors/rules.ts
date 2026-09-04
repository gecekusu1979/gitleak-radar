import { DetectionRule } from "../types/index.js";

export const DETECTION_RULES: DetectionRule[] = [
  {
    id: "aws-access-key",
    name: "AWS Access Key",
    description: "Identifies standard AWS Access Key IDs (AKIA...)",
    severity: "critical",
    pattern: /\b(AKIA[0-9A-Z]{16})\b/g,
    keywords: ["AKIA"]
  },
  {
    id: "aws-secret-key",
    name: "AWS Secret Access Key",
    description: "Identifies high-entropy AWS Secret Access Key patterns",
    severity: "critical",
    pattern: /(?:aws_secret_access_key|aws_secret_key|secret_key)\s*[:=]\s*["']?([A-Za-z0-9\/+=]{40})["']?/gi,
    keywords: ["aws_secret", "secret_key"]
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
    id: "jwt",
    name: "JSON Web Token (JWT)",
    description: "Identifies hardcoded base64-encoded JWT signatures",
    severity: "high",
    pattern: /\b(ey[A-Za-z0-9-_=]+\.ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+)\b/g,
    keywords: ["ey"]
  },
  {
    id: "private-key",
    name: "Private Key",
    description: "Identifies RSA, EC, OPENSSH or standard Private Keys",
    severity: "critical",
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
    keywords: ["BEGIN", "PRIVATE KEY"]
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
    pattern: /\b(AIza[0-9A-Za-z\\-_]{35})\b/g,
    keywords: ["AIza"]
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
    id: "generic-api-key",
    name: "Generic API Key",
    description: "Identifies assignments of high-entropy strings to api_key variables",
    severity: "medium",
    pattern: /(?:api_key|apikey|secret|api_token)\s*[:=]\s*["']?([A-Za-z0-9\-_]{20,64})["']?/gi,
    keywords: ["api_key", "apikey", "secret", "api_token"]
  },
  {
    id: "generic-bearer-token",
    name: "Generic Bearer Token",
    description: "Identifies hardcoded Bearer authorization tokens",
    severity: "high",
    pattern: /(?:bearer)\s+([A-Za-z0-9\-._~+/]{20,}=*)/gi,
    keywords: ["bearer"]
  },
  {
    id: "generic-password",
    name: "Generic Password Assignment",
    description: "Identifies static password variable definitions",
    severity: "medium",
    pattern: /(?:password|passwd|pwd)\s*[:=]\s*["']?([^"'\s#]{8,64})["']?/gi,
    keywords: ["password", "passwd", "pwd"]
  }
];
