'use strict';

var crypto = require('crypto');
var stream = require('stream');
var string_decoder = require('string_decoder');
var fs = require('fs');
var path = require('path');
var http = require('http');

// src/patterns/credentials.ts
var anthropicApiKeyPattern = {
  id: "anthropic-api-key",
  name: "Anthropic API Key",
  category: "credential",
  severity: "critical",
  regex: /\bsk-ant-(?:api03|admin01)-[A-Za-z0-9_\-]{80,120}(?![A-Za-z0-9_])|\bsk-ant-[A-Za-z0-9_\-]{20,}(?![A-Za-z0-9_])/g,
  placeholder: "ANTHROPIC_API_KEY",
  description: "Anthropic Claude API key or Admin key"
};
var openaiApiKeyPattern = {
  id: "openai-api-key",
  name: "OpenAI API Key",
  category: "credential",
  severity: "critical",
  regex: /\bsk-(?:proj|svcacct)-[A-Za-z0-9_\-]{40,}(?![A-Za-z0-9_])|\bsk-[a-zA-Z0-9]{20,}\b/g,
  placeholder: "OPENAI_API_KEY",
  description: "OpenAI API key (standard, project, or service account)"
};
var awsAccessKeyPattern = {
  id: "aws-access-key-id",
  name: "AWS Access Key ID",
  category: "credential",
  severity: "high",
  regex: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g,
  placeholder: "AWS_ACCESS_KEY_ID",
  description: "Amazon Web Services 20-character Access Key ID"
};
var awsSecretKeyPattern = {
  id: "aws-secret-access-key",
  name: "AWS Secret Access Key",
  category: "credential",
  severity: "critical",
  regex: /(?:aws_secret_access_key|aws_secret_key|secret_access_key)[\s=:'"]+([A-Za-z0-9\/+=]{40})(?:\s|$|['",;])/gi,
  secretGroup: 1,
  placeholder: "AWS_SECRET_ACCESS_KEY",
  description: "Amazon Web Services 40-character Secret Access Key"
};
var githubTokenPattern = {
  id: "github-token",
  name: "GitHub Token",
  category: "credential",
  severity: "critical",
  regex: /\b(?:ghp_[A-Za-z0-9]{36,40}|github_pat_[A-Za-z0-9_]{60,100}|gho_[A-Za-z0-9]{36,40}|ghu_[A-Za-z0-9]{36,40}|ghs_[A-Za-z0-9]{36,40}|ghr_[A-Za-z0-9]{36,40})\b/g,
  placeholder: "GITHUB_TOKEN",
  description: "GitHub Personal Access Token, OAuth token, or App token"
};
var stripeKeyPattern = {
  id: "stripe-api-key",
  name: "Stripe API Key",
  category: "credential",
  severity: "critical",
  // Unbounded: Stripe documents that key length may grow, and a bounded
  // quantifier followed by \b silently skips longer keys entirely.
  regex: /\b(?:sk|pk|rk)_(?:live|test)_[0-9a-zA-Z]{24,}\b/g,
  placeholder: "STRIPE_API_KEY",
  description: "Stripe API key (live or test, secret or publishable)"
};
var jwtTokenPattern = {
  id: "jwt-token",
  name: "JSON Web Token (JWT)",
  category: "credential",
  severity: "critical",
  regex: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-]{10,}(?![A-Za-z0-9_])/g,
  placeholder: "JWT_TOKEN",
  description: "JSON Web Token (JWT) in header.payload.signature format"
};
var privateKeyPattern = {
  id: "private-key",
  name: "Private Key",
  category: "credential",
  severity: "critical",
  // The body may not run past another BEGIN marker: without that, every unterminated
  // BEGIN rescanned to the end of the input (quadratic on many BEGINs without END).
  regex: /-----BEGIN (?:(?:RSA |OPENSSH |DSA |EC |ENCRYPTED )?PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----(?:(?!-----BEGIN )[\s\S])*?-----END (?:(?:RSA |OPENSSH |DSA |EC |ENCRYPTED )?PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----/g,
  placeholder: "PRIVATE_KEY",
  description: "RSA, OpenSSH, DSA, EC, Encrypted, or PGP private key certificate"
};
var googleApiKeyPattern = {
  id: "google-api-key",
  name: "Google API Key",
  category: "credential",
  severity: "high",
  regex: /\bAIza[0-9A-Za-z\-_]{35}(?![A-Za-z0-9_])/g,
  placeholder: "GOOGLE_API_KEY",
  description: "Google Cloud or Gemini AI Studio API key"
};
var slackTokenPattern = {
  id: "slack-token",
  name: "Slack Token",
  category: "credential",
  severity: "high",
  // Bot tokens have two numeric segments, user/refresh tokens have three
  regex: /\b(?:xoxb|xoxp|xoxr|xoxa|xoxe|xoxs)-[0-9]{10,13}(?:-[0-9]{10,13}){1,2}-[a-zA-Z0-9]{24,34}\b|\bxapp-[0-9]{1,}-[a-zA-Z0-9]{10,32}-[0-9]{10,13}-[a-zA-Z0-9]{24,64}\b/g,
  placeholder: "SLACK_TOKEN",
  description: "Slack Bot, User, or App token"
};
var databaseUrlPattern = {
  id: "database-url",
  name: "Database Connection URL",
  category: "credential",
  severity: "critical",
  regex: /\b(?:postgres|postgresql|mysql|mariadb|mongodb|mongodb\+srv|redis|rediss):\/\/[^\s:/@]*:[^\s/@]+@[^\s/:]+(?::\d+)?(?:\/[^\s?"']*)?(?:\?[^\s"']*)?\b/g,
  placeholder: "DATABASE_URL",
  description: "Database connection URL containing user and password credentials"
};
var databaseUriPattern = databaseUrlPattern;
var basicAuthUrlPattern = {
  id: "basic-auth-url",
  name: "HTTP Basic Auth URL",
  category: "credential",
  severity: "critical",
  regex: /\bhttps?:\/\/[^\s:/@]+:[^\s/@]+@[^\s/:]+(?::\d+)?(?:\/[^\s?"']*)?(?:\?[^\s"']*)?\b/g,
  placeholder: "BASIC_AUTH_URL",
  description: "HTTP/HTTPS URL containing username and password credentials"
};
var huggingFaceTokenPattern = {
  id: "huggingface-token",
  name: "Hugging Face Token",
  category: "credential",
  severity: "high",
  regex: /\bhf_[a-zA-Z0-9]{34}\b/g,
  placeholder: "HUGGINGFACE_TOKEN",
  description: "Hugging Face User Access Token"
};
var gitlabTokenPattern = {
  id: "gitlab-token",
  name: "GitLab Token",
  category: "credential",
  severity: "high",
  regex: /\bglpat-[0-9a-zA-Z\-_]{20,}(?![A-Za-z0-9_])/g,
  placeholder: "GITLAB_TOKEN",
  description: "GitLab Personal Access Token"
};
var discordTokenPattern = {
  id: "discord-token",
  name: "Discord Bot Token",
  category: "credential",
  severity: "high",
  regex: /\b[MNO][a-zA-Z0-9_-]{23,25}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27,38}(?![A-Za-z0-9_])/g,
  placeholder: "DISCORD_TOKEN",
  description: "Discord Bot Authentication Token"
};
var npmTokenPattern = {
  id: "npm-token",
  name: "NPM Access Token",
  category: "credential",
  severity: "critical",
  regex: /\bnpm_[A-Za-z0-9]{36}\b/g,
  placeholder: "NPM_TOKEN",
  description: "Node Package Manager (npm) access token"
};
var sendgridApiKeyPattern = {
  id: "sendgrid-api-key",
  name: "SendGrid API Key",
  category: "credential",
  severity: "high",
  regex: /\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}(?![A-Za-z0-9_])/g,
  placeholder: "SENDGRID_API_KEY",
  description: "SendGrid Email API key"
};
var twilioAccountSidPattern = {
  id: "twilio-account-sid",
  name: "Twilio Account SID",
  category: "credential",
  severity: "high",
  regex: /\bAC[0-9a-fA-F]{32}\b/g,
  placeholder: "TWILIO_ACCOUNT_SID",
  description: "Twilio Account Identifier"
};
var supabaseKeyPattern = {
  id: "supabase-key",
  name: "Supabase Key",
  category: "credential",
  severity: "critical",
  regex: /\bsbp_[a-zA-Z0-9]{40}\b/g,
  placeholder: "SUPABASE_KEY",
  description: "Supabase Project or Management API key"
};
var telegramBotTokenPattern = {
  id: "telegram-bot-token",
  name: "Telegram Bot Token",
  category: "credential",
  severity: "critical",
  regex: /\b\d{8,10}:[A-Za-z0-9_-]{35}(?![A-Za-z0-9_])/g,
  placeholder: "TELEGRAM_BOT_TOKEN",
  description: "Telegram Bot API authentication token"
};
var twilioApiKeyPattern = {
  id: "twilio-api-key",
  name: "Twilio API Key",
  category: "credential",
  severity: "critical",
  regex: /\bSK[0-9a-fA-F]{32}\b/g,
  placeholder: "TWILIO_API_KEY",
  description: "Twilio API Key starting with SK prefix"
};
var azureStorageKeyPattern = {
  id: "azure-storage-key",
  name: "Azure Storage Key",
  category: "credential",
  severity: "critical",
  regex: /\bAccountKey=[A-Za-z0-9+/]{86}==|\bAccountKey=[A-Za-z0-9+/=]{88}\b/g,
  placeholder: "AZURE_STORAGE_KEY",
  description: "Azure Storage Account access key"
};
var gcpOauthSecretPattern = {
  id: "gcp-oauth-client-secret",
  name: "GCP OAuth Client Secret",
  category: "credential",
  severity: "critical",
  regex: /\bGOCSPX-[A-Za-z0-9_-]{28}(?![A-Za-z0-9_])/g,
  placeholder: "GCP_OAUTH_CLIENT_SECRET",
  description: "Google Cloud Platform OAuth 2.0 client secret"
};
var digitalOceanTokenPattern = {
  id: "digitalocean-token",
  name: "DigitalOcean Token",
  category: "credential",
  severity: "critical",
  regex: /\bdop_v1_[a-f0-9]{64}\b/g,
  placeholder: "DIGITALOCEAN_TOKEN",
  description: "DigitalOcean Personal Access Token"
};
var mailgunApiKeyPattern = {
  id: "mailgun-api-key",
  name: "Mailgun API Key",
  category: "credential",
  severity: "high",
  regex: /\bkey-[0-9a-zA-Z]{32}\b/g,
  placeholder: "MAILGUN_API_KEY",
  description: "Mailgun API authentication key"
};
var openrouterApiKeyPattern = {
  id: "openrouter-api-key",
  name: "OpenRouter API Key",
  category: "credential",
  severity: "critical",
  regex: /\bsk-or-v1-[a-f0-9]{40,}(?![A-Za-z0-9_])/g,
  placeholder: "OPENROUTER_API_KEY",
  description: "OpenRouter API key (sk-or-v1-...)"
};
var groqApiKeyPattern = {
  id: "groq-api-key",
  name: "Groq API Key",
  category: "credential",
  severity: "critical",
  regex: /\bgsk_[A-Za-z0-9]{40,}(?![A-Za-z0-9_])/g,
  placeholder: "GROQ_API_KEY",
  description: "Groq API key (gsk_...)"
};
var xaiApiKeyPattern = {
  id: "xai-api-key",
  name: "xAI API Key",
  category: "credential",
  severity: "critical",
  regex: /\bxai-[A-Za-z0-9_]{60,}(?![A-Za-z0-9_])/g,
  placeholder: "XAI_API_KEY",
  description: "xAI (Grok) API key (xai-...)"
};
var perplexityApiKeyPattern = {
  id: "perplexity-api-key",
  name: "Perplexity API Key",
  category: "credential",
  severity: "critical",
  regex: /\bpplx-[A-Za-z0-9]{32,}(?![A-Za-z0-9_])/g,
  placeholder: "PERPLEXITY_API_KEY",
  description: "Perplexity API key (pplx-...)"
};
var replicateApiTokenPattern = {
  id: "replicate-api-token",
  name: "Replicate API Token",
  category: "credential",
  severity: "critical",
  regex: /\br8_[A-Za-z0-9_-]{30,}(?![A-Za-z0-9_-])/g,
  placeholder: "REPLICATE_API_TOKEN",
  description: "Replicate API token (r8_...)"
};
var huggingFaceOrgTokenPattern = {
  id: "huggingface-org-token",
  name: "Hugging Face Organization Token",
  category: "credential",
  severity: "high",
  regex: /\bapi_org_[A-Za-z0-9]{30,}(?![A-Za-z0-9_])/g,
  placeholder: "HUGGINGFACE_ORG_TOKEN",
  description: "Hugging Face organization API token (api_org_...)"
};
var langsmithApiKeyPattern = {
  id: "langsmith-api-key",
  name: "LangSmith API Key",
  category: "credential",
  severity: "high",
  regex: /\blsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10}(?![A-Za-z0-9_])/g,
  placeholder: "LANGSMITH_API_KEY",
  description: "LangSmith / LangChain personal or service key (lsv2_pt_ / lsv2_sk_)"
};
var CREDENTIAL_PATTERNS = [
  anthropicApiKeyPattern,
  openaiApiKeyPattern,
  awsAccessKeyPattern,
  awsSecretKeyPattern,
  githubTokenPattern,
  stripeKeyPattern,
  jwtTokenPattern,
  privateKeyPattern,
  googleApiKeyPattern,
  slackTokenPattern,
  databaseUrlPattern,
  basicAuthUrlPattern,
  huggingFaceTokenPattern,
  gitlabTokenPattern,
  discordTokenPattern,
  npmTokenPattern,
  sendgridApiKeyPattern,
  twilioAccountSidPattern,
  supabaseKeyPattern,
  telegramBotTokenPattern,
  twilioApiKeyPattern,
  azureStorageKeyPattern,
  gcpOauthSecretPattern,
  digitalOceanTokenPattern,
  mailgunApiKeyPattern,
  openrouterApiKeyPattern,
  groqApiKeyPattern,
  xaiApiKeyPattern,
  perplexityApiKeyPattern,
  replicateApiTokenPattern,
  huggingFaceOrgTokenPattern,
  langsmithApiKeyPattern
];

// src/patterns/context.ts
var MIN_SECRET_LENGTH = 8;
var REFERENCE_HINT = /\$\{|\$\(|^\$[A-Za-z_]|^%[A-Za-z_]\w*%$|\{\{|\{%|<%|`|process\.env|import\.meta\.env|os\.environ|getenv\s*\(|Deno\.env/i;
var PLACEHOLDER_HINT = /^<.*>$|^\[.*\]$|^your[-_ ]|[-_ ]here$|example|placeholder|change[-_]?me|changeit|dummy|redacted|x{4,}|\*{3,}|•{3,}|\.{3}|…/i;
var DUMMY_WORD = /^(?:password|passwd|secret|undefined|null|none|nil|true|false)$/i;
var SINGLE_REPEATED_CHAR = /^(.)\1*$/s;
function isPlausibleSecretValue(value) {
  if (value.length < MIN_SECRET_LENGTH) return false;
  if (SINGLE_REPEATED_CHAR.test(value)) return false;
  return !REFERENCE_HINT.test(value) && !PLACEHOLDER_HINT.test(value) && !DUMMY_WORD.test(value);
}
var CODE_IDENTIFIER = /^[a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)*$/;
var npmrcAuthPattern = {
  id: "npmrc-auth",
  name: "npm Registry Credential (.npmrc)",
  category: "credential",
  severity: "critical",
  // '#' and ';' stay in the value: cutting there could leave the rest of a token visible
  regex: /^[ \t]*(?:\/\/[^\s=]*:)?(?:_authToken|_auth|_password)[ \t]*=[ \t]*["']?([^\s"']+)/gm,
  secretGroup: 1,
  validator: (v) => isPlausibleSecretValue(v) && !/[()]/.test(v) && !CODE_IDENTIFIER.test(v),
  placeholder: "NPMRC_AUTH",
  description: ".npmrc _authToken, _auth or _password value"
};
var netrcPasswordPattern = {
  id: "netrc-password",
  name: "netrc Password",
  category: "credential",
  severity: "high",
  regex: /(?<!\S)(?:machine[ \t]+\S+|default)(?:\s+(?:login|account|port)[ \t]+\S+)*\s+password[ \t]+(\S+)/g,
  secretGroup: 1,
  validator: isPlausibleSecretValue,
  placeholder: "NETRC_PASSWORD",
  description: "Password of a .netrc machine or default entry"
};
function isBase64UserPassword(value) {
  let decoded;
  try {
    decoded = atob(value);
  } catch {
    return false;
  }
  const colon = decoded.indexOf(":");
  return /^[\x20-\x7e]+$/.test(decoded) && colon > 0 && colon < decoded.length - 1;
}
var dockerConfigAuthPattern = {
  id: "docker-config-auth",
  name: "Docker Registry Auth (config.json)",
  category: "credential",
  severity: "high",
  regex: /"auth"[ \t]*:[ \t]*"([A-Za-z0-9+/]{8,}={0,2})"/g,
  secretGroup: 1,
  validator: isBase64UserPassword,
  placeholder: "DOCKER_AUTH",
  description: 'Base64 user:password in a Docker config.json "auth" field'
};
var dotenvSecretPattern = {
  id: "dotenv-secret",
  name: "Secret in .env Assignment",
  category: "credential",
  severity: "high",
  regex: /(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|SECRET_(?:ACCESS_)?KEY(?:_BASE)?)(?:_?[0-9]{1,3})?(?=[ \t]*=)(?<=^[ \t]*(?:-[ \t]+)?(?:(?:export|ENV|ARG|set|SET)[ \t]+)?[A-Z][A-Z0-9_]*)[ \t]*=[ \t]*["']?((?<=")(?:[^"\\\r\n]|\\.)+(?=")|(?<=')[^'\r\n]+(?=')|(?<==)\S+(?:[ \t]+(?!#)\S+)*)/gm,
  secretGroup: 1,
  validator: isPlausibleSecretValue,
  placeholder: "ENV_SECRET",
  description: "Value of an UPPERCASE PASSWORD / SECRET / TOKEN / API_KEY variable"
};
function isNameLike(value) {
  return new RegExp("^\\??\\p{L}+(?:[-_.]\\p{L}+)*$", "u").test(value);
}
var quotedSecretAssignmentPattern = {
  id: "quoted-secret-assignment",
  name: "Quoted Secret Assignment",
  category: "credential",
  severity: "high",
  // Starts at the keyword (cheap to scan for); (?![\w.-]) makes it the end of the key name
  regex: /(?:password|passwd|passphrase|[_.-]pass|secret|secret[_.-]?key|api[_.-]?key|token)(?![\w.-])(?<!(?:page|next|prev|sync|continuation|cancellation|csrf|xsrf|cursor|resume|bos|eos|pad|unk|sep|cls|mask|stop)[_.-]?token)\\?["']?[ \t]*(?:=>|:=|[:=])[ \t]*\\?["']((?<=\\")[^"\\\r\n]+(?=\\")|(?<=")(?:[^"\\\r\n]|\\.)+(?=")|(?<=')(?:[^'\\\r\n]|\\.|'')+(?='))/gi,
  secretGroup: 1,
  // No whitespace (UI labels and messages) and no letters-only names (see isNameLike)
  validator: (v) => isPlausibleSecretValue(v) && !/\s/.test(v) && !isNameLike(v),
  placeholder: "QUOTED_SECRET",
  description: "Quoted value assigned to a password, secret, token or API key"
};
var KIND_SECRET_LINE = /^kind[ \t]*:[ \t]*(["']?)Secret\1[ \t]*(?:#.*)?$/;
var DATA_KEY_LINE = /^(?:data|stringData)[ \t]*:(?=[ \t]|$)/;
function buildLineTable(text) {
  const t = { start: [], end: [], indent: [], col: [], blank: [], boundary: [], nextFilled: [] };
  let pos = 0;
  for (; ; ) {
    let nl = text.indexOf("\n", pos);
    if (nl === -1) nl = text.length;
    let end = nl;
    if (end > pos && text.charCodeAt(end - 1) === 13) end--;
    let i = pos;
    while (i < end && text.charCodeAt(i) === 32) i++;
    const indent = i - pos;
    const blank = i >= end || text.charCodeAt(i) === 35;
    const boundary = indent === 0 && (text.startsWith("---", pos) && (end - pos === 3 || /\s/.test(text[pos + 3] ?? "")) || end - pos === 3 && text.startsWith("...", pos));
    while (i < end && text.charCodeAt(i) === 45 && (i + 1 === end || text.charCodeAt(i + 1) === 32 || text.charCodeAt(i + 1) === 9)) {
      i++;
      while (i < end && (text.charCodeAt(i) === 32 || text.charCodeAt(i) === 9)) i++;
    }
    t.start.push(pos);
    t.end.push(end);
    t.indent.push(indent);
    t.col.push(i - pos);
    t.blank.push(blank);
    t.boundary.push(boundary);
    if (nl === text.length) break;
    pos = nl + 1;
  }
  const n = t.start.length;
  t.nextFilled = new Array(n + 1);
  t.nextFilled[n] = n;
  for (let k = n - 1; k >= 0; k--) t.nextFilled[k] = t.blank[k] ? t.nextFilled[k + 1] : k;
  return t;
}
function closingQuote(text, open, end) {
  const q = text.charCodeAt(open);
  for (let i = open + 1; i < end; i++) {
    const c = text.charCodeAt(i);
    if (q === 34 && c === 92) {
      i++;
    } else if (c === q) {
      if (q === 39 && text.charCodeAt(i + 1) === 39) {
        i++;
        continue;
      }
      return i;
    }
  }
  return -1;
}
function afterKey(text, p, end) {
  let i = p;
  const c = text.charCodeAt(p);
  if (c === 34 || c === 39) {
    const close = closingQuote(text, p, end);
    if (close === -1) return -1;
    i = close + 1;
    while (i < end && (text.charCodeAt(i) === 32 || text.charCodeAt(i) === 9)) i++;
    return i < end && text.charCodeAt(i) === 58 ? i + 1 : -1;
  }
  for (; ; ) {
    const colon = text.indexOf(":", i);
    if (colon === -1 || colon >= end) return -1;
    const next = text.charCodeAt(colon + 1);
    if (colon + 1 === end || next === 32 || next === 9) return colon + 1;
    i = colon + 1;
  }
}
function detectKubernetesSecretValues(text) {
  const t = buildLineTable(text);
  const n = t.start.length;
  const spans = [];
  const doneUntil = /* @__PURE__ */ new Map();
  const contentStart = (k) => t.start[k] + t.col[k];
  const lastDeeper = (from, indent) => {
    let last = from;
    for (let j = t.nextFilled[from + 1]; j < n; j = t.nextFilled[j + 1]) {
      if (t.boundary[j] || t.indent[j] <= indent) break;
      last = j;
    }
    return last;
  };
  for (let k = t.nextFilled[0]; k < n; k = t.nextFilled[k + 1]) {
    const c = t.col[k];
    const s = contentStart(k);
    if (!text.startsWith("kind", s) || !KIND_SECRET_LINE.test(text.slice(s, t.end[k]))) continue;
    if ((doneUntil.get(c) ?? -1) >= k) continue;
    let a = k;
    if (t.indent[k] === c) {
      for (let j = k - 1; j >= 0; j--) {
        if (t.boundary[j]) break;
        if (t.blank[j]) continue;
        if (t.indent[j] >= c) {
          a = j;
          continue;
        }
        if (t.col[j] === c) a = j;
        break;
      }
    }
    let b = k;
    for (let j = t.nextFilled[k + 1]; j < n; j = t.nextFilled[j + 1]) {
      if (t.boundary[j] || t.indent[j] < c) break;
      b = j;
    }
    doneUntil.set(c, b);
    for (let d = a; d <= b; d = t.nextFilled[d + 1]) {
      if (t.col[d] !== c || t.indent[d] !== c && d !== a) continue;
      const ds = contentStart(d);
      const key = DATA_KEY_LINE.exec(text.slice(ds, t.end[d]));
      if (!key) continue;
      const blockEnd = lastDeeper(d, c);
      let v = ds + key[0].length;
      while (v < t.end[d] && (text.charCodeAt(v) === 32 || text.charCodeAt(v) === 9)) v++;
      if (v < t.end[d] && text.charCodeAt(v) !== 35) {
        spans.push([v, t.end[blockEnd]]);
        continue;
      }
      for (let j = t.nextFilled[d + 1]; j <= blockEnd && j < n; j = t.nextFilled[j + 1]) {
        const entryIndent = t.indent[j];
        const last = lastDeeper(j, entryIndent);
        const p = t.start[j] + t.col[j];
        const lineEnd = t.end[j];
        const colonEnd = t.col[j] === entryIndent ? afterKey(text, p, lineEnd) : -1;
        if (colonEnd === -1) {
          spans.push([p, t.end[last]]);
          j = last;
          continue;
        }
        let vs = colonEnd;
        while (vs < lineEnd && (text.charCodeAt(vs) === 32 || text.charCodeAt(vs) === 9)) vs++;
        const ch = text.charCodeAt(vs);
        if (vs >= lineEnd || ch === 35 || ch === 124 || ch === 62) {
          if (last > j) {
            const first = t.nextFilled[j + 1];
            spans.push([t.start[first] + t.indent[first], t.end[last]]);
          }
        } else if (ch === 34 || ch === 39) {
          const close = closingQuote(text, vs, lineEnd);
          spans.push([vs + 1, close === -1 ? t.end[last] : close]);
        } else if (last > j) {
          spans.push([vs, t.end[last]]);
        } else {
          let e = lineEnd;
          const comment = text.slice(vs, lineEnd).search(/[ \t]#/);
          if (comment !== -1) e = vs + comment;
          while (e > vs && (text.charCodeAt(e - 1) === 32 || text.charCodeAt(e - 1) === 9)) e--;
          spans.push([vs, e]);
        }
        j = last;
      }
    }
  }
  return spans;
}
var kubernetesSecretPattern = {
  id: "kubernetes-secret",
  name: "Kubernetes Secret Value",
  category: "credential",
  severity: "high",
  // Gate only: the values are found by `detect`
  regex: /^[ \t]*(?:-[ \t]+)*kind[ \t]*:[ \t]*["']?Secret["']?[ \t]*(?:#.*)?\r?$/m,
  detect: detectKubernetesSecretValues,
  // Skip templates and our own placeholders, so redacted output is never redacted again
  validator: (v) => v.trim().length > 0 && !/\{\{|\$\{|\{%/.test(v) && !/^\[[A-Z][A-Z0-9_]*\]$/.test(v.trim()),
  placeholder: "K8S_SECRET_VALUE",
  description: "Value under data/stringData of a Kubernetes Secret manifest"
};
var CONTEXT_PATTERNS = [
  npmrcAuthPattern,
  netrcPasswordPattern,
  dockerConfigAuthPattern,
  dotenvSecretPattern,
  quotedSecretAssignmentPattern,
  kubernetesSecretPattern
];

// src/patterns/pii.ts
var emailPattern = {
  id: "email-address",
  name: "Email Address",
  category: "pii",
  severity: "medium",
  // RFC 5321 length limits (local part 64, domain 253, label 63) keep matching linear;
  // unbounded quantifiers backtracked quadratically on inputs like "a-a-a-..." (80KB took 10 s).
  regex: /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}\b/g,
  placeholder: "EMAIL_ADDRESS",
  description: "Standard RFC 5322 email address"
};
var ipv4Pattern = {
  id: "ipv4-address",
  name: "IPv4 Address",
  category: "network",
  severity: "low",
  // Skip four-part version numbers introduced by v / ver / version (see tests/audit-round5).
  // `\b` before the keyword keeps words that merely end in "ver" (e.g. server=) matching.
  regex: /(?<!\b(?:[vV](?:er(?:sion)?)?|VER(?:SION)?)[\s:=]{0,2})\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b/g,
  placeholder: "IPV4_ADDRESS",
  description: "Standard IPv4 network address"
};
var ssnPattern = {
  id: "us-ssn",
  name: "US Social Security Number",
  category: "pii",
  severity: "critical",
  regex: /\b\d{3}-\d{2}-\d{4}\b/g,
  placeholder: "US_SSN",
  description: "US Social Security Number in AAA-GG-SSSS format"
};
function isValidLuhn(numStr) {
  const digits = numStr.replace(/\D/g, "");
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let shouldDouble = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = parseInt(digits.charAt(i), 10);
    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}
var creditCardPattern = {
  id: "credit-card",
  name: "Credit Card Number",
  category: "pii",
  severity: "critical",
  regex: /\b(?:4[0-9]{3}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{1,4}|5[1-5][0-9]{2}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}|2[2-7][0-9]{2}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}|3[47][0-9]{2}[- ]?[0-9]{6}[- ]?[0-9]{5}|6(?:011|5[0-9]{2})[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4})\b/g,
  placeholder: "CREDIT_CARD",
  description: "Major credit card numbers (Visa, MasterCard, Amex, Discover)",
  validator: isValidLuhn
};
var ipv6Pattern = {
  id: "ipv6-address",
  name: "IPv6 Address",
  category: "network",
  severity: "low",
  regex: /(?<![a-zA-Z0-9_:])(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|:(?::[0-9a-fA-F]{1,4}){1,7}|(?:[0-9a-fA-F]{1,4}:){1,6}:(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}|::[1])(?![a-zA-Z0-9_:])/gi,
  placeholder: "IPV6_ADDRESS",
  description: "Standard or compressed 128-bit IPv6 address",
  validator: isLikelyIpv6
};
var IPV6_LOOPBACK = ["", "", "1"].join(":");
function isLikelyIpv6(candidate) {
  if (candidate === IPV6_LOOPBACK) return true;
  const groups = candidate.split(":").filter((g) => g.length > 0);
  if (groups.length < 2) return false;
  if (!/[0-9]/.test(candidate)) return false;
  if (groups.length === 2 && candidate.includes("::") && groups[0].length < 3) return false;
  return true;
}
var phonePattern = {
  id: "phone-number",
  name: "Phone Number",
  category: "pii",
  severity: "medium",
  regex: /(?:(?<![\w$])\+(?:[0-9]{1,4}[-.\s](?:\([0-9]{1,4}\)[-.\s]?)?[0-9]{1,4}[-.\s]?[0-9]{1,4}[-.\s]?[0-9]{1,9}|[0-9]{7,15})\b|(?:\([0-9]{3}\)|\b[0-9]{3})[-.\s][0-9]{3}[-.\s][0-9]{4}\b|(?<![\w$])\b0[35789](?:[0-9]{8}|[0-9]{2}[-.\s][0-9]{3}[-.\s][0-9]{3}|[0-9][-.\s][0-9]{3}[-.\s][0-9]{4})\b|(?<![\w$])\b02(?:[48][-.\s]?[0-9]{4}[-.\s]?[0-9]{4}|[0-35-79][0-9][-.\s]?[0-9]{3}[-.\s]?[0-9]{3,4})\b)/g,
  placeholder: "PHONE_NUMBER",
  description: "Telephone number in formatted local, international E.164, or domestic VN format"
};
var PII_PATTERNS = [
  emailPattern,
  ipv4Pattern,
  ipv6Pattern,
  phonePattern,
  ssnPattern,
  creditCardPattern
];

// src/patterns/vn.ts
function hasValidProvinceCode(id) {
  const province = Number(id.slice(0, 3));
  return province >= 1 && province <= 96;
}
var vnCitizenIdPattern = {
  id: "vn-citizen-id",
  name: "Vietnamese Citizen ID (CCCD)",
  category: "pii",
  severity: "high",
  regex: /(?<![\w$])0\d{11}(?!\d)/g,
  placeholder: "VN_CITIZEN_ID",
  description: "12-digit Vietnamese citizen identity card number (CCCD) with a valid province code",
  validator: hasValidProvinceCode
};
var vnIdNumberPattern = {
  id: "vn-id-number",
  name: "Vietnamese ID Number (CMND/CCCD, with context)",
  category: "pii",
  severity: "high",
  regex: /(?:CMND|CCCD|CMT|căn cước|can cuoc|chứng minh|chung minh)(?:\s+(?:số|so|no\.?))?[\s:#.=-]*(\d{9}|\d{12})(?!\d)/giu,
  secretGroup: 1,
  placeholder: "VN_ID_NUMBER",
  description: "9-digit CMND or 12-digit CCCD number preceded by an ID keyword"
};
var vnTaxCodePattern = {
  id: "vn-tax-code",
  name: "Vietnamese Tax Code (MST)",
  category: "pii",
  severity: "medium",
  regex: /(?:MST|mã số thuế|ma so thue|tax\s*code)[\s:#.=-]*(\d{10}(?:-\d{3})?)(?!\d)/giu,
  secretGroup: 1,
  placeholder: "VN_TAX_CODE",
  description: "10- or 13-digit Vietnamese tax code preceded by MST / m\xE3 s\u1ED1 thu\u1EBF"
};
var vnBankAccountPattern = {
  id: "vn-bank-account",
  name: "Vietnamese Bank Account Number",
  category: "pii",
  severity: "high",
  regex: /(?:STK|số tài khoản|so tai khoan|tài khoản số|tai khoan so|account\s*(?:no\.?|number))[\s:#.=-]*(\d{6,20})(?!\d)/giu,
  secretGroup: 1,
  placeholder: "VN_BANK_ACCOUNT",
  description: "Bank account number preceded by STK / s\u1ED1 t\xE0i kho\u1EA3n / account number"
};
var VN_PII_PATTERNS = [
  vnCitizenIdPattern,
  vnIdNumberPattern,
  vnTaxCodePattern,
  vnBankAccountPattern
];

// src/patterns/presets.ts
var PATTERN_PRESETS = {
  "vn-pii": VN_PII_PATTERNS
};
function resolvePresets(names) {
  if (!names || names.length === 0) return [];
  const out = [];
  for (const name of names) {
    const preset = PATTERN_PRESETS[name];
    if (!preset) {
      throw new Error(`Unknown preset "${name}". Available presets: ${Object.keys(PATTERN_PRESETS).join(", ")}`);
    }
    out.push(...preset);
  }
  return out;
}

// src/patterns/index.ts
var DEFAULT_PATTERNS = [
  ...CREDENTIAL_PATTERNS,
  ...CONTEXT_PATTERNS,
  ...PII_PATTERNS
];
var PATTERN_MAP = new Map([
  ...DEFAULT_PATTERNS.map((p) => [p.id, p]),
  ["database-uri", databaseUrlPattern]
  // Alias for backwards compatibility
]);

// src/core/entropy.ts
var DEFAULT_ENTROPY_MIN_LENGTH = 20;
var DEFAULT_ENTROPY_MAX_LENGTH = 120;
function calculateShannonEntropy(str) {
  if (!str || str.length === 0) {
    return 0;
  }
  const frequencies = /* @__PURE__ */ new Map();
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    frequencies.set(char, (frequencies.get(char) ?? 0) + 1);
  }
  let entropy = 0;
  const len = str.length;
  for (const count of frequencies.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return Math.round(entropy * 1e3) / 1e3;
}
function isHighEntropyToken(token, config = {}) {
  const minLength = config.minLength ?? DEFAULT_ENTROPY_MIN_LENGTH;
  const maxLength = config.maxLength ?? DEFAULT_ENTROPY_MAX_LENGTH;
  const base64Threshold = config.base64Threshold ?? 4.3;
  const hexThreshold = config.hexThreshold ?? 3.2;
  if (token.length < minLength || token.length > maxLength) {
    return false;
  }
  const entropy = calculateShannonEntropy(token);
  const isHex = /^[0-9a-fA-F]+$/.test(token);
  if (isHex) {
    return entropy >= hexThreshold;
  }
  return entropy >= base64Threshold;
}
function createHighEntropyPattern(config = {}) {
  const min = config.minLength ?? DEFAULT_ENTROPY_MIN_LENGTH;
  return {
    id: "generic-high-entropy-secret",
    name: "Generic High-Entropy Secret",
    category: "credential",
    severity: "high",
    regex: new RegExp(
      `(?:api[_-]?key|secret|token|password|auth[_-]?key|access[_-]?key)[\\s=:'"]+([^\\s"';,\\n]{${min},})`,
      "gi"
    ),
    secretGroup: 1,
    placeholder: "GENERIC_SECRET",
    description: "High-entropy random token detected in sensitive assignment context"
  };
}

// src/core/vault.ts
function collectPlaceholderLiterals(text) {
  const found = /* @__PURE__ */ new Set();
  for (const m of text.matchAll(/\[[^[\]\r\n]{1,256}_\d+\]/g)) {
    found.add(m[0]);
  }
  return found;
}
var Vault = class _Vault {
  placeholderToEntry = /* @__PURE__ */ new Map();
  placeholderToEntries = /* @__PURE__ */ new Map();
  originalToPlaceholder = /* @__PURE__ */ new Map();
  counters = /* @__PURE__ */ new Map();
  maxEntries;
  /** Names (never values) of placeholders dropped by the size cap, oldest first */
  evictedPlaceholders = /* @__PURE__ */ new Set();
  /** Bumped on every change to the placeholder set; invalidates the cached unmask regex */
  mutations = 0;
  unmaskRegexCache;
  constructor(options) {
    this.maxEntries = options?.maxEntries;
  }
  /**
   * True when `prefix` is the beginning of at least one known placeholder.
   * Used by streaming unmaskers to decide whether a chunk tail must be held back.
   */
  hasPlaceholderPrefix(prefix) {
    for (const placeholder of this.placeholderToEntries.keys()) {
      if (placeholder.startsWith(prefix)) return true;
    }
    return false;
  }
  getUnmaskRegex() {
    if (this.unmaskRegexCache?.mutations !== this.mutations) {
      const escaped = Array.from(this.placeholderToEntries.keys()).sort((a, b) => b.length - a.length).map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
      this.unmaskRegexCache = { mutations: this.mutations, regex: new RegExp(escaped.join("|"), "g") };
    }
    const { regex } = this.unmaskRegexCache;
    regex.lastIndex = 0;
    return regex;
  }
  evictOldestIfNeeded() {
    if (this.maxEntries && this.originalToPlaceholder.size >= this.maxEntries) {
      const oldestPlaceholder = this.placeholderToEntry.keys().next().value;
      if (oldestPlaceholder) {
        for (const entry of this.placeholderToEntries.get(oldestPlaceholder) ?? []) {
          if (this.originalToPlaceholder.get(entry.original) === oldestPlaceholder) {
            this.originalToPlaceholder.delete(entry.original);
          }
        }
        this.placeholderToEntry.delete(oldestPlaceholder);
        this.placeholderToEntries.delete(oldestPlaceholder);
        this.mutations++;
        this.rememberEvicted(oldestPlaceholder);
      }
    }
  }
  rememberEvicted(placeholder) {
    this.evictedPlaceholders.add(placeholder);
    const limit = (this.maxEntries ?? 0) * 10 || 1e5;
    if (this.evictedPlaceholders.size > limit) {
      const oldest = this.evictedPlaceholders.values().next().value;
      if (oldest !== void 0) this.evictedPlaceholders.delete(oldest);
    }
  }
  /**
   * Placeholders present in `text` that were evicted by the `maxEntries` cap and
   * therefore cannot be restored by `unmask`. Returns placeholder names only.
   */
  findEvictedPlaceholders(text) {
    if (this.evictedPlaceholders.size === 0 || !text) return [];
    return [...this.evictedPlaceholders].filter(
      (p) => text.includes(p) && !this.placeholderToEntries.has(p)
    );
  }
  /**
   * Retrieves an existing placeholder or allocates a new numbered placeholder
   * for the given secret token. Optionally ensures placeholder does not collide
   * with literal text already in the document.
   */
  getOrCreate(original, pattern, existingText) {
    const existing = this.originalToPlaceholder.get(original);
    if (existing) {
      return existing;
    }
    this.evictOldestIfNeeded();
    let count = (this.counters.get(pattern.placeholder) ?? 0) + 1;
    if (existingText) {
      const isTaken = typeof existingText === "string" ? (p) => existingText.includes(p) : (p) => existingText.has(p);
      while (isTaken(`[${pattern.placeholder}_${count}]`)) {
        count++;
      }
    }
    this.counters.set(pattern.placeholder, count);
    const placeholder = `[${pattern.placeholder}_${count}]`;
    const entry = {
      placeholder,
      original,
      patternId: pattern.id,
      category: pattern.category,
      timestamp: Date.now()
    };
    this.placeholderToEntry.set(placeholder, entry);
    this.placeholderToEntries.set(placeholder, [entry]);
    this.originalToPlaceholder.set(original, placeholder);
    this.mutations++;
    return placeholder;
  }
  /**
   * Retrieves original secret from placeholder.
   */
  getOriginal(placeholder) {
    return this.placeholderToEntry.get(placeholder)?.original;
  }
  /**
   * Replaces all placeholders in a string back with their original secrets
   * in a deterministic, collision-free single regex pass. Handles multiple
   * secrets mapped to identical custom placeholders sequentially.
   *
   * @param encode Optional transform applied to each restored secret, e.g. JSON string
   *   escaping when the placeholder sits inside a JSON document.
   */
  unmask(text, encode) {
    if (this.placeholderToEntries.size === 0 || !text) {
      return text;
    }
    const regex = this.getUnmaskRegex();
    const occurrences = /* @__PURE__ */ new Map();
    const out = (secret) => encode ? encode(secret) : secret;
    return text.replace(regex, (matched) => {
      const list = this.placeholderToEntries.get(matched);
      if (!list || list.length === 0) {
        return matched;
      }
      if (list.length === 1) {
        return out(list[0].original);
      }
      const idx = occurrences.get(matched) ?? 0;
      occurrences.set(matched, idx + 1);
      const entry = list[idx % list.length];
      return out(entry.original);
    });
  }
  /**
   * Directly restores an entry into the vault without altering placeholder names.
   */
  restoreEntry(entry) {
    if (!this.originalToPlaceholder.has(entry.original)) {
      this.evictOldestIfNeeded();
    }
    this.placeholderToEntry.set(entry.placeholder, entry);
    const existingList = this.placeholderToEntries.get(entry.placeholder) ?? [];
    if (!existingList.some((e) => e.original === entry.original)) {
      existingList.push(entry);
    }
    this.placeholderToEntries.set(entry.placeholder, existingList);
    this.originalToPlaceholder.set(entry.original, entry.placeholder);
    this.mutations++;
    const match = entry.placeholder.match(/^\[(.*)_(\d+)\]$/);
    if (match && match[1] && match[2]) {
      const prefix = match[1];
      const num = parseInt(match[2], 10);
      const current = this.counters.get(prefix) ?? 0;
      if (num > current) {
        this.counters.set(prefix, num);
      }
    }
  }
  /**
   * Restores a list of entries into the vault.
   */
  restoreEntries(entries) {
    for (const entry of entries) {
      this.restoreEntry(entry);
    }
  }
  /**
   * Serializes the vault entries to JSON string.
   */
  toJSON() {
    return JSON.stringify(this.entries(), null, 2);
  }
  /**
   * Deserializes a JSON string or array of entries into a new Vault instance.
   */
  static fromJSON(data) {
    const vault = new _Vault();
    const list = typeof data === "string" ? JSON.parse(data) : data;
    if (!Array.isArray(list)) {
      throw new Error("Invalid vault: expected a JSON array of entries");
    }
    list.forEach((entry, i) => {
      const e = entry;
      if (!e || typeof e !== "object" || typeof e.placeholder !== "string" || e.placeholder.length === 0 || typeof e.original !== "string" || e.original.length === 0) {
        throw new Error(
          `Invalid vault: entry ${i} must have non-empty string "placeholder" and "original" fields`
        );
      }
    });
    vault.restoreEntries(list);
    return vault;
  }
  /**
   * Returns list of all entries currently in the vault.
   */
  entries() {
    const all = [];
    for (const list of this.placeholderToEntries.values()) {
      all.push(...list);
    }
    return all;
  }
  /**
   * Number of unique secrets stored.
   */
  get size() {
    return this.originalToPlaceholder.size;
  }
  /**
   * Wipes all secrets from memory.
   */
  clear() {
    this.placeholderToEntry.clear();
    this.placeholderToEntries.clear();
    this.originalToPlaceholder.clear();
    this.counters.clear();
    this.evictedPlaceholders.clear();
    this.mutations++;
  }
};

// src/core/engine.ts
var SEVERITY_WEIGHT = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1
};
function selectSecretSpan(match, pattern) {
  let group = pattern.secretGroup;
  if (group === void 0 && match.groups?.["secret"] !== void 0) {
    group = "secret";
  }
  if (group !== void 0) {
    const value = typeof group === "number" ? match[group] : match.groups?.[group];
    const span = typeof group === "number" ? match.indices?.[group] : match.indices?.groups?.[group];
    if (value && span) {
      return { secret: value, startIndex: span[0], endIndex: span[1] };
    }
  }
  return { secret: match[0], startIndex: match.index, endIndex: match.index + match[0].length };
}
var RedactEngine = class {
  patterns;
  vault;
  constructor(options) {
    this.patterns = options?.patterns ?? [...DEFAULT_PATTERNS];
    this.vault = options?.vault;
  }
  /**
   * Redacts sensitive secrets and PII from the input string.
   */
  redact(text, options) {
    const startTime = performance.now();
    const reversible = options?.reversible ?? false;
    const vault = options?.vault ?? this.vault ?? (reversible ? new Vault() : void 0);
    const presetPatterns = resolvePresets(options?.presets);
    let activePatterns = [...this.patterns, ...presetPatterns, ...options?.customPatterns ?? []];
    if (options?.detectHighEntropy) {
      activePatterns.push(createHighEntropyPattern(options.entropy));
    }
    if (options?.include && options.include.length > 0) {
      const includeSet = new Set(options.include);
      const customIds = new Set([...options.customPatterns ?? [], ...presetPatterns].map((p) => p.id));
      activePatterns = activePatterns.filter(
        (p) => includeSet.has(p.id) || customIds.has(p.id) || options.detectHighEntropy && p.id === "generic-high-entropy-secret"
      );
    }
    if (options?.exclude && options.exclude.length > 0) {
      const excludeSet = new Set(options.exclude);
      activePatterns = activePatterns.filter((p) => !excludeSet.has(p.id));
    }
    const allowlist = options?.allowlist ?? [];
    const rawMatches = [];
    const consider = (pattern, secret, startIndex, endIndex) => {
      if (allowlist.length > 0 && allowlist.some((al) => typeof al === "string" && al.length > 0 && secret === al)) {
        return;
      }
      if (pattern.validator && !pattern.validator(secret)) {
        return;
      }
      if (pattern.id === "generic-high-entropy-secret") {
        const entropyConfig = options?.entropy;
        const maxLength = entropyConfig?.maxLength ?? DEFAULT_ENTROPY_MAX_LENGTH;
        const sample = secret.length > maxLength ? secret.slice(0, maxLength) : secret;
        if (!isHighEntropyToken(sample, entropyConfig)) {
          return;
        }
      }
      rawMatches.push({ pattern, secret, startIndex, endIndex });
    };
    for (const pattern of activePatterns) {
      if (pattern.detect) {
        const gate = new RegExp(pattern.regex.source, pattern.regex.flags.replace(/[gy]/g, ""));
        if (!gate.test(text)) continue;
        for (const [startIndex, endIndex] of pattern.detect(text)) {
          if (!(startIndex >= 0 && endIndex > startIndex && endIndex <= text.length)) continue;
          consider(pattern, text.slice(startIndex, endIndex), startIndex, endIndex);
        }
        continue;
      }
      let flags = pattern.regex.flags;
      if (!flags.includes("g")) flags += "g";
      if (!flags.includes("d")) flags += "d";
      const regex = new RegExp(pattern.regex.source, flags);
      let match;
      while ((match = regex.exec(text)) !== null) {
        if (match[0].length === 0) {
          regex.lastIndex++;
          continue;
        }
        const { secret, startIndex, endIndex } = selectSecretSpan(match, pattern);
        consider(pattern, secret, startIndex, endIndex);
      }
    }
    rawMatches.sort((a, b) => {
      const weightA = SEVERITY_WEIGHT[a.pattern.severity] ?? 0;
      const weightB = SEVERITY_WEIGHT[b.pattern.severity] ?? 0;
      if (weightA !== weightB) {
        return weightB - weightA;
      }
      const lenA = a.endIndex - a.startIndex;
      const lenB = b.endIndex - b.startIndex;
      if (lenA !== lenB) {
        return lenB - lenA;
      }
      return a.startIndex - b.startIndex;
    });
    const accepted = [];
    const covered = rawMatches.length > 1 ? new Uint8Array(text.length) : void 0;
    for (const candidate of rawMatches) {
      if (covered) {
        if (covered.subarray(candidate.startIndex, candidate.endIndex).includes(1)) {
          continue;
        }
        covered.fill(1, candidate.startIndex, candidate.endIndex);
      }
      accepted.push(candidate);
    }
    accepted.sort((a, b) => a.startIndex - b.startIndex);
    const matches = [];
    const stats = {};
    let redactedText = "";
    let cursor = 0;
    let literalPlaceholders;
    for (let i = 0; i < accepted.length; i++) {
      const m = accepted[i];
      let replacement;
      if (options?.customFormatter) {
        replacement = options.customFormatter({
          pattern: m.pattern,
          matchedText: m.secret,
          index: i + 1,
          reversible
        });
        if (reversible && vault) {
          const existingOriginal = vault.getOriginal(replacement);
          if (existingOriginal !== void 0 && existingOriginal !== m.secret) {
            throw new Error(
              `customFormatter returned the same placeholder "${replacement}" for two different secrets. Reversible mode requires a unique placeholder per secret (e.g. include info.index or a hash).`
            );
          }
          vault.restoreEntry({
            placeholder: replacement,
            original: m.secret,
            patternId: m.pattern.id,
            category: m.pattern.category,
            timestamp: Date.now()
          });
        }
      } else if (reversible && vault) {
        literalPlaceholders ??= collectPlaceholderLiterals(text);
        replacement = vault.getOrCreate(m.secret, m.pattern, literalPlaceholders);
      } else {
        replacement = `[REDACTED_${m.pattern.placeholder}]`;
      }
      redactedText += text.slice(cursor, m.startIndex);
      redactedText += replacement;
      cursor = m.endIndex;
      const matchItem = {
        patternId: m.pattern.id,
        patternName: m.pattern.name,
        category: m.pattern.category,
        severity: m.pattern.severity,
        startIndex: m.startIndex,
        endIndex: m.endIndex,
        replacement
      };
      if (options?.includeMatchedText) {
        matchItem.matchedText = m.secret;
      }
      matches.push(matchItem);
      stats[m.pattern.id] = (stats[m.pattern.id] ?? 0) + 1;
    }
    redactedText += text.slice(cursor);
    const durationMs = Math.round((performance.now() - startTime) * 100) / 100;
    const resultObj = {
      text: redactedText,
      matches,
      hasLeaks: matches.length > 0,
      totalLeaks: matches.length,
      stats,
      durationMs
    };
    if (vault) {
      Object.defineProperty(resultObj, "vault", {
        value: vault,
        enumerable: false,
        writable: true,
        configurable: true
      });
    }
    Object.defineProperty(resultObj, "toJSON", {
      value: function() {
        return {
          text: this.text,
          hasLeaks: this.hasLeaks,
          totalLeaks: this.totalLeaks,
          stats: this.stats,
          durationMs: this.durationMs,
          matches: this.matches
        };
      },
      enumerable: false,
      writable: true,
      configurable: true
    });
    return resultObj;
  }
  /**
   * Unmasks a string using the provided Vault instance.
   */
  unmask(text, vault) {
    return vault.unmask(text);
  }
};
var defaultEngine = new RedactEngine();
function redact(text, options) {
  return defaultEngine.redact(text, options);
}
function unmask(text, vault) {
  return defaultEngine.unmask(text, vault);
}
var FORMAT = "agent-redact-vault";
var VERSION = 1;
var KDF = { name: "scrypt", N: 32768, r: 8, p: 1 };
function headerAad(file) {
  return Buffer.from(JSON.stringify([file.format, file.version, file.kdf, file.cipher]), "utf8");
}
var SCRYPT_MAXMEM = 64 * 1024 * 1024;
function deriveKey(passphrase, salt) {
  return crypto.scryptSync(passphrase.normalize("NFC"), salt, 32, { N: KDF.N, r: KDF.r, p: KDF.p, maxmem: SCRYPT_MAXMEM });
}
function hasExpectedKdf(kdf) {
  const k = kdf;
  return !!k && k["name"] === KDF.name && k["N"] === KDF.N && k["r"] === KDF.r && k["p"] === KDF.p && typeof k["salt"] === "string" && Buffer.from(k["salt"], "base64").length === 16;
}
function isEncryptedVault(content) {
  try {
    const parsed = JSON.parse(content);
    return parsed?.format === FORMAT;
  } catch {
    return false;
  }
}
function encryptVaultJson(json, passphrase) {
  if (typeof passphrase !== "string" || passphrase.length === 0) {
    throw new Error("A non-empty passphrase is required to encrypt a vault");
  }
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const kdf = { ...KDF, salt: salt.toString("base64") };
  const header = { format: FORMAT, version: VERSION, kdf, cipher: "aes-256-gcm" };
  const cipher = crypto.createCipheriv("aes-256-gcm", deriveKey(passphrase, salt), iv);
  cipher.setAAD(headerAad(header));
  const data = Buffer.concat([cipher.update(json, "utf8"), cipher.final()]);
  const file = {
    ...header,
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    data: data.toString("base64")
  };
  return JSON.stringify(file, null, 2) + "\n";
}
function decryptVaultJson(content, passphrase) {
  const fail = () => new Error("Cannot decrypt vault: wrong passphrase or corrupted file");
  let file;
  try {
    file = JSON.parse(content);
  } catch {
    throw fail();
  }
  if (file?.format !== FORMAT || file.version !== VERSION || file.cipher !== "aes-256-gcm" || !hasExpectedKdf(file.kdf)) {
    throw fail();
  }
  try {
    const key = deriveKey(passphrase, Buffer.from(file.kdf.salt, "base64"));
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(file.iv, "base64"));
    decipher.setAAD(headerAad(file));
    decipher.setAuthTag(Buffer.from(file.tag, "base64"));
    return Buffer.concat([decipher.update(Buffer.from(file.data, "base64")), decipher.final()]).toString("utf8");
  } catch {
    throw fail();
  }
}
var PEM_BEGIN_PATTERN = /-----BEGIN (?:(?:RSA |OPENSSH |DSA |EC |ENCRYPTED )?PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----/;
var PEM_END_PATTERN = /-----END (?:(?:RSA |OPENSSH |DSA |EC |ENCRYPTED )?PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----(?:\r?\n)?/;
var MAX_OPEN_PEM_BUFFER = 1048576;
var RedactTransformStream = class extends stream.Transform {
  buffer = "";
  /** True while discarding the body of an oversized private key block that has no END yet */
  droppingOpenPem = false;
  decoder = new string_decoder.StringDecoder("utf8");
  options;
  vault;
  constructor(options = {}) {
    super({ objectMode: false });
    this.options = options;
    this.vault = options.vault ?? new Vault();
  }
  _transform(chunk, _encoding, callback) {
    const text = typeof chunk === "string" ? chunk : this.decoder.write(chunk);
    this.buffer += text;
    if (this.droppingOpenPem) {
      const endMatch = this.buffer.match(PEM_END_PATTERN);
      if (!endMatch || endMatch.index === void 0) {
        this.buffer = this.buffer.slice(-64);
        callback();
        return;
      }
      this.buffer = this.buffer.slice(endMatch.index + endMatch[0].length);
      this.droppingOpenPem = false;
    }
    let pemEndMatch = this.buffer.match(PEM_END_PATTERN);
    while (pemEndMatch && pemEndMatch.index !== void 0) {
      const pemEnd = pemEndMatch.index + pemEndMatch[0].length;
      const pemSlice = this.buffer.slice(0, pemEnd);
      this.buffer = this.buffer.slice(pemEnd);
      const res = redact(pemSlice, {
        ...this.options,
        vault: this.vault
      });
      if (this.options.onLineRedacted && res.hasLeaks) {
        this.options.onLineRedacted(res);
      }
      this.push(res.text);
      pemEndMatch = this.buffer.match(PEM_END_PATTERN);
    }
    const lastBegin = this.buffer.search(PEM_BEGIN_PATTERN);
    if (lastBegin !== -1) {
      const remaining = this.buffer.slice(lastBegin);
      if (!PEM_END_PATTERN.test(remaining)) {
        if (this.buffer.length < MAX_OPEN_PEM_BUFFER) {
          callback();
          return;
        }
        const before = this.buffer.slice(0, lastBegin);
        const prefixRes = redact(before, { ...this.options, vault: this.vault });
        this.push(prefixRes.text + "[REDACTED_PRIVATE_KEY]\n");
        this.buffer = this.buffer.slice(-64);
        this.droppingOpenPem = true;
        callback();
        return;
      }
    }
    const lines = this.buffer.split("\n");
    this.buffer = lines.pop() ?? "";
    for (const line of lines) {
      const res = redact(line, {
        ...this.options,
        vault: this.vault
      });
      if (this.options.onLineRedacted && res.hasLeaks) {
        this.options.onLineRedacted(res);
      }
      this.push(res.text + "\n");
    }
    callback();
  }
  _flush(callback) {
    this.buffer += this.decoder.end();
    if (this.droppingOpenPem) {
      const endMatch = this.buffer.match(PEM_END_PATTERN);
      this.buffer = endMatch && endMatch.index !== void 0 ? this.buffer.slice(endMatch.index + endMatch[0].length) : "";
      this.droppingOpenPem = false;
    }
    if (this.buffer.length > 0) {
      const lastBegin = this.buffer.search(PEM_BEGIN_PATTERN);
      if (lastBegin !== -1 && !PEM_END_PATTERN.test(this.buffer.slice(lastBegin))) {
        const before = this.buffer.slice(0, lastBegin);
        const prefixRes = redact(before, { ...this.options, vault: this.vault });
        this.push(prefixRes.text + "[REDACTED_PRIVATE_KEY]");
      } else {
        const res = redact(this.buffer, {
          ...this.options,
          vault: this.vault
        });
        this.push(res.text);
      }
      this.buffer = "";
    }
    callback();
  }
};
function createRedactStream(options) {
  return new RedactTransformStream(options);
}

// src/core/deep.ts
var isPlainObject = (v) => {
  if (typeof v !== "object" || v === null) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
};
function isToolUnmaskAllowed(policy, toolName) {
  if (policy === true) return true;
  if (typeof policy === "function") return policy(toolName);
  return false;
}
var nameOf = (parent) => {
  for (const k of ["name", "toolName", "tool_name"]) {
    if (typeof parent[k] === "string") return parent[k];
  }
  return "";
};
function toolInputSlot(key, parent) {
  const type = typeof parent["type"] === "string" ? parent["type"] : "";
  if (key === "arguments" || key === "args" || key === "partial_json") return nameOf(parent);
  if ((key === "input" || key === "parameters") && (/tool|function/i.test(type) || "toolName" in parent)) {
    return nameOf(parent);
  }
  if (key === "delta" && /function_call_arguments/i.test(type)) return "";
  return null;
}
var BASE64_RE = /^[A-Za-z0-9+/_-]*={0,2}$/;
var TEXT_MIME_RE = /^(?:text\/|application\/(?:json|xml|yaml|x-yaml|toml|x-toml|javascript|ecmascript|x-sh|x-shellscript|sql|csv|x-ndjson)\b)|\+(?:json|xml)\b/i;
function findBase64Payload(value, key, parent) {
  const dataUrl = /^data:([^;,]*)((?:;[^;,]*)*);base64,/i.exec(value.slice(0, 512));
  if (dataUrl) {
    const head = dataUrl[0];
    return { mime: dataUrl[1] || void 0, encoded: value.slice(head.length), rebuild: (e) => head + e };
  }
  if (key === "data" && parent && (parent["type"] === "base64" || "media_type" in parent || "mime_type" in parent)) {
    const mime = parent["media_type"] ?? parent["mime_type"];
    return { mime: typeof mime === "string" ? mime : void 0, encoded: value, rebuild: (e) => e };
  }
  return null;
}
function mapStrings(value, fn, skipProp, seen = /* @__PURE__ */ new WeakMap(), key, parent) {
  if (typeof value === "string") return fn(value, key, parent);
  if (Array.isArray(value)) {
    if (seen.has(value)) return seen.get(value);
    const out = [];
    seen.set(value, out);
    for (const item of value) out.push(mapStrings(item, fn, skipProp, seen, key, parent));
    return out;
  }
  if (isPlainObject(value)) {
    if (seen.has(value)) return seen.get(value);
    const out = {};
    seen.set(value, out);
    for (const [k, v] of Object.entries(value)) {
      const decision = skipProp(k, value);
      out[k] = decision === "skip" ? v : mapStrings(v, fn, decision === "all" ? () => void 0 : skipProp, seen, k, value);
    }
    return out;
  }
  return value;
}
function redactDeep(value, options = {}) {
  const { vault = new Vault(), skipKeys = [], ...redactOptions } = options;
  const reversible = redactOptions.reversible ?? true;
  const skip = new Set(skipKeys);
  const stats = {};
  let totalLeaks = 0;
  const scan = (s) => {
    const res = redact(s, { ...redactOptions, reversible, vault });
    totalLeaks += res.totalLeaks;
    for (const [id, n] of Object.entries(res.stats)) stats[id] = (stats[id] ?? 0) + n;
    return res.text;
  };
  const out = mapStrings(
    value,
    (s, key, parent) => {
      const payload = findBase64Payload(s, key, parent);
      if (payload) {
        const compact = payload.encoded.replace(/\r?\n/g, "");
        if (BASE64_RE.test(compact)) {
          const bytes = Buffer.from(compact, "base64");
          const textual = payload.mime !== void 0 && TEXT_MIME_RE.test(payload.mime) || !bytes.includes(0);
          if (!textual) return s;
          const decoded = bytes.toString("utf8");
          const redacted = scan(decoded);
          return redacted === decoded ? s : payload.rebuild(Buffer.from(redacted, "utf8").toString("base64"));
        }
      }
      return scan(s);
    },
    (k) => skip.has(k) ? "skip" : void 0
  );
  return { value: out, vault, totalLeaks, stats };
}
function unmaskDeep(value, vault, options = {}) {
  const policy = options.unmaskToolInputs;
  return mapStrings(
    value,
    (s) => vault.unmask(s),
    (k, parent) => {
      const tool = toolInputSlot(k, parent);
      if (tool === null) return void 0;
      return isToolUnmaskAllowed(policy, tool) ? "all" : "skip";
    }
  );
}

// src/core/unmask-stream.ts
var jsonStringEscape = (secret) => JSON.stringify(secret).slice(1, -1);
var StreamingUnmasker = class {
  constructor(vault, encode) {
    this.vault = vault;
    this.encode = encode;
  }
  vault;
  encode;
  pending = "";
  /** Feeds the next chunk and returns the text that is safe to emit now */
  push(chunk) {
    const text = this.pending + chunk;
    this.pending = "";
    const hold = this.holdStart(text);
    if (hold === -1) {
      return this.vault.unmask(text, this.encode);
    }
    this.pending = text.slice(hold);
    return this.vault.unmask(text.slice(0, hold), this.encode);
  }
  /** Returns everything still buffered (call once the stream has ended) */
  flush() {
    const rest = this.pending;
    this.pending = "";
    return this.vault.unmask(rest, this.encode);
  }
  holdStart(text) {
    const open = text.lastIndexOf("[");
    if (open === -1) return -1;
    const tail = text.slice(open);
    if (tail.includes("]")) return -1;
    return this.vault.hasPlaceholderPrefix(tail) ? open : -1;
  }
};
async function* unmaskTextStream(source, vault) {
  const unmasker = new StreamingUnmasker(vault);
  for await (const chunk of source) {
    const out = unmasker.push(String(chunk));
    if (out) yield out;
  }
  const rest = unmasker.flush();
  if (rest) yield rest;
}
var UnmaskTransformStream = class extends stream.Transform {
  decoder = new string_decoder.StringDecoder("utf8");
  unmasker;
  constructor(vault) {
    super();
    this.unmasker = new StreamingUnmasker(vault);
  }
  _transform(chunk, _enc, callback) {
    const text = typeof chunk === "string" ? chunk : this.decoder.write(chunk);
    const out = this.unmasker.push(text);
    if (out) this.push(out);
    callback();
  }
  _flush(callback) {
    const rest = this.unmasker.push(this.decoder.end()) + this.unmasker.flush();
    if (rest) this.push(rest);
    callback();
  }
};
function createUnmaskStream(vault) {
  return new UnmaskTransformStream(vault);
}
var ANTHROPIC_ENVELOPE_EVENTS = /* @__PURE__ */ new Set([
  "message_start",
  "content_block_start",
  "content_block_stop",
  "message_delta",
  "message_stop",
  "ping"
]);
var isObject = (v) => typeof v === "object" && v !== null;
function getOrCreate(map, key, create) {
  let value = map.get(key);
  if (value === void 0) {
    value = create();
    map.set(key, value);
  }
  return value;
}
async function* unmaskAnthropicStream(events, vault, options = {}) {
  const policy = options.unmaskToolInputs;
  const text = /* @__PURE__ */ new Map();
  const json = /* @__PURE__ */ new Map();
  const toolNames = /* @__PURE__ */ new Map();
  function* flushBlock(index) {
    const t = text.get(index)?.flush();
    if (t) yield { type: "content_block_delta", index, delta: { type: "text_delta", text: t } };
    const j = json.get(index)?.flush();
    if (j) yield { type: "content_block_delta", index, delta: { type: "input_json_delta", partial_json: j } };
    text.delete(index);
    json.delete(index);
  }
  for await (const event of events) {
    const e = event;
    if (isObject(e) && e["type"] === "content_block_start" && isObject(e["content_block"])) {
      const block = e["content_block"];
      if (block["type"] === "tool_use") toolNames.set(Number(e["index"] ?? 0), String(block["name"] ?? ""));
    }
    if (isObject(e) && e["type"] === "content_block_delta" && isObject(e["delta"])) {
      const index = Number(e["index"] ?? 0);
      const delta = e["delta"];
      if (delta["type"] === "text_delta" && typeof delta["text"] === "string") {
        const out = getOrCreate(text, index, () => new StreamingUnmasker(vault)).push(delta["text"]);
        yield { ...e, delta: { ...delta, text: out } };
        continue;
      }
      if (delta["type"] === "input_json_delta" && typeof delta["partial_json"] === "string") {
        if (!isToolUnmaskAllowed(policy, toolNames.get(index) ?? "")) {
          yield { ...e, delta: { ...delta } };
          continue;
        }
        const out = getOrCreate(json, index, () => new StreamingUnmasker(vault, jsonStringEscape)).push(
          delta["partial_json"]
        );
        yield { ...e, delta: { ...delta, partial_json: out } };
        continue;
      }
    }
    if (isObject(e) && e["type"] === "content_block_stop") {
      yield* flushBlock(Number(e["index"] ?? 0));
    }
    if (isObject(e) && e["type"] === "message_stop") {
      for (const index of /* @__PURE__ */ new Set([...text.keys(), ...json.keys()])) yield* flushBlock(index);
    }
    if (isObject(e) && typeof e["type"] === "string" && ANTHROPIC_ENVELOPE_EVENTS.has(e["type"])) {
      yield unmaskDeep(event, vault, { unmaskToolInputs: policy });
    } else {
      yield event;
    }
  }
  for (const index of /* @__PURE__ */ new Set([...text.keys(), ...json.keys()])) yield* flushBlock(index);
}
async function* unmaskOpenAIStream(chunks, vault, options = {}) {
  const policy = options.unmaskToolInputs;
  const content = /* @__PURE__ */ new Map();
  const args = /* @__PURE__ */ new Map();
  const toolNames = /* @__PURE__ */ new Map();
  for await (const chunk of chunks) {
    const c = chunk;
    if (!isObject(c) || !Array.isArray(c["choices"])) {
      yield chunk;
      continue;
    }
    const choices = c["choices"].map((choice) => {
      if (!isObject(choice) || !isObject(choice["delta"])) return choice;
      const index = Number(choice["index"] ?? 0);
      const delta = { ...choice["delta"] };
      const finished = choice["finish_reason"] != null;
      if (typeof delta["content"] === "string" || finished && content.has(index)) {
        const u = getOrCreate(content, index, () => new StreamingUnmasker(vault));
        let out = typeof delta["content"] === "string" ? u.push(delta["content"]) : "";
        if (finished) out += u.flush();
        if (typeof delta["content"] === "string" || out) delta["content"] = out;
      }
      const toolCalls = Array.isArray(delta["tool_calls"]) ? [...delta["tool_calls"]] : [];
      const mapped = toolCalls.map((tc) => {
        if (!isObject(tc) || !isObject(tc["function"]) || typeof tc["function"]["arguments"] !== "string") {
          return tc;
        }
        const key = `${index}:${Number(tc["index"] ?? 0)}`;
        if (typeof tc["function"]["name"] === "string") toolNames.set(key, tc["function"]["name"]);
        if (!isToolUnmaskAllowed(policy, toolNames.get(key) ?? "")) {
          return { ...tc, function: { ...tc["function"] } };
        }
        const u = getOrCreate(args, key, () => new StreamingUnmasker(vault, jsonStringEscape));
        return { ...tc, function: { ...tc["function"], arguments: u.push(tc["function"]["arguments"]) } };
      });
      if (finished) {
        for (const [key, u] of args) {
          if (!key.startsWith(`${index}:`)) continue;
          const rest = u.flush();
          if (rest) mapped.push({ index: Number(key.split(":")[1]), function: { arguments: rest } });
          args.delete(key);
        }
        content.delete(index);
      }
      if (mapped.length > 0) delta["tool_calls"] = mapped;
      return { ...choice, delta };
    });
    yield { ...c, choices };
  }
  const trailing = [];
  for (const [index, u] of content) {
    const rest = u.flush();
    if (rest) trailing.push({ index, delta: { content: rest }, finish_reason: null });
  }
  for (const [key, u] of args) {
    const rest = u.flush();
    if (!rest) continue;
    const [choiceIndex, toolIndex] = key.split(":").map(Number);
    trailing.push({ index: choiceIndex, delta: { tool_calls: [{ index: toolIndex, function: { arguments: rest } }] }, finish_reason: null });
  }
  if (trailing.length > 0) yield { choices: trailing };
}
var DEFAULT_CONFIG_FILENAMES = [
  "agent-redact.config.json",
  ".agentredactrc.json",
  ".agentredactrc"
];
function parseRegexString(patternStr) {
  const match = patternStr.match(/^\/(.+)\/([a-z]*)$/);
  if (match && match[1]) {
    const flags = match[2]?.includes("g") ? match[2] : (match[2] ?? "") + "g";
    return new RegExp(match[1], flags);
  }
  return new RegExp(patternStr, "g");
}
function resolveCustomPattern(cfg) {
  const label = typeof cfg?.id === "string" && cfg.id ? `"${cfg.id}"` : "(missing id)";
  for (const field of ["id", "name", "regex", "placeholder"]) {
    const value = cfg?.[field];
    if (typeof value !== "string" || value.trim().length === 0) {
      throw new Error(`Custom pattern ${label}: "${field}" must be a non-empty string`);
    }
  }
  if (cfg.secretGroup !== void 0 && !(typeof cfg.secretGroup === "number" && Number.isInteger(cfg.secretGroup) && cfg.secretGroup > 0 || typeof cfg.secretGroup === "string" && cfg.secretGroup.length > 0)) {
    throw new Error(`Custom pattern ${label}: "secretGroup" must be a positive integer or a group name`);
  }
  return {
    id: cfg.id,
    name: cfg.name,
    category: cfg.category ?? "custom",
    severity: cfg.severity ?? "high",
    regex: parseRegexString(cfg.regex),
    placeholder: cfg.placeholder,
    description: cfg.description ?? cfg.name,
    ...cfg.secretGroup !== void 0 ? { secretGroup: cfg.secretGroup } : {}
  };
}
function loadConfig(explicitPath, searchDir = process.cwd()) {
  let targetPath;
  if (explicitPath) {
    const resolved = path.resolve(searchDir, explicitPath);
    if (!fs.existsSync(resolved)) {
      throw new Error(`Config file not found at: ${resolved}`);
    }
    targetPath = resolved;
  } else {
    for (const filename of DEFAULT_CONFIG_FILENAMES) {
      const candidate = path.join(searchDir, filename);
      if (fs.existsSync(candidate)) {
        targetPath = candidate;
        break;
      }
    }
  }
  if (!targetPath) {
    return null;
  }
  try {
    const raw = fs.readFileSync(targetPath, "utf-8");
    const parsed = JSON.parse(raw);
    const resolvedCustomPatterns = parsed.customPatterns?.map(resolveCustomPattern);
    if (parsed.presets !== void 0) {
      if (!Array.isArray(parsed.presets) || parsed.presets.some((p) => typeof p !== "string")) {
        throw new Error('"presets" must be an array of preset names');
      }
      resolvePresets(parsed.presets);
    }
    return {
      ...parsed,
      customPatterns: resolvedCustomPatterns
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Failed to parse agent-redact config at ${targetPath}: ${msg}`);
  }
}

// src/middleware/universal.ts
function wrapAgent(agentFn, options = {}) {
  const { unmaskResponse = true, unmaskToolInputs, onLeakDetected, ...redactOptions } = options;
  return async (rawPrompt) => {
    const vault = new Vault();
    const redactResult = redact(rawPrompt, {
      ...redactOptions,
      reversible: true,
      vault
    });
    if (redactResult.hasLeaks && onLeakDetected) {
      onLeakDetected({
        result: redactResult,
        originalPrompt: rawPrompt,
        sanitizedPrompt: redactResult.text
      });
    }
    const agentResponse = await agentFn(redactResult.text);
    if (!unmaskResponse) {
      return agentResponse;
    }
    if (typeof agentResponse === "string") {
      return unmask(agentResponse, vault);
    }
    if (isAsyncGenerator(agentResponse)) {
      return unmaskMixedStream(agentResponse, vault, unmaskToolInputs);
    }
    return unmaskDeep(agentResponse, vault, { unmaskToolInputs });
  };
}
function isAsyncGenerator(value) {
  return typeof value === "object" && value !== null && value[Symbol.toStringTag] === "AsyncGenerator";
}
async function* unmaskMixedStream(source, vault, unmaskToolInputs) {
  const unmasker = new StreamingUnmasker(vault);
  for await (const item of source) {
    if (typeof item === "string") {
      const out = unmasker.push(item);
      if (out) yield out;
    } else {
      const pending = unmasker.flush();
      if (pending) yield pending;
      yield unmaskDeep(item, vault, { unmaskToolInputs });
    }
  }
  const rest = unmasker.flush();
  if (rest) yield rest;
}

// src/middleware/express.ts
function createExpressMiddleware(options = {}) {
  const {
    targetFields = ["prompt", "message", "content", "input", "system", "text", "query"],
    ...redactOpts
  } = options;
  return (req, _res, next) => {
    if (!req.body || typeof req.body !== "object") {
      return next();
    }
    const vault = new Vault();
    let totalLeaks = 0;
    const combinedStats = {};
    const allMatches = [];
    const redactObject = (obj) => {
      for (const [key, value] of Object.entries(obj)) {
        if (typeof value === "string" && targetFields.includes(key)) {
          const result = redact(value, { ...redactOpts, reversible: true, vault });
          obj[key] = result.text;
          if (result.hasLeaks) {
            totalLeaks += result.totalLeaks;
            allMatches.push(...result.matches);
            for (const [pId, count] of Object.entries(result.stats)) {
              combinedStats[pId] = (combinedStats[pId] ?? 0) + count;
            }
          }
        } else if (Array.isArray(value)) {
          for (let i = 0; i < value.length; i++) {
            const item = value[i];
            if (typeof item === "string" && targetFields.includes(key)) {
              const result = redact(item, { ...redactOpts, reversible: true, vault });
              value[i] = result.text;
              if (result.hasLeaks) {
                totalLeaks += result.totalLeaks;
                allMatches.push(...result.matches);
                for (const [pId, count] of Object.entries(result.stats)) {
                  combinedStats[pId] = (combinedStats[pId] ?? 0) + count;
                }
              }
            } else if (item && typeof item === "object") {
              redactObject(item);
            }
          }
        } else if (value && typeof value === "object") {
          redactObject(value);
        }
      }
    };
    redactObject(req.body);
    req.redact = {
      vault,
      totalLeaks,
      hasLeaks: totalLeaks > 0,
      stats: combinedStats,
      matches: allMatches
    };
    next();
  };
}
var DEFAULT_UPSTREAM = {
  anthropic: "https://api.anthropic.com",
  openai: "https://api.openai.com"
};
var DEFAULT_MAX_BODY = 32 * 1024 * 1024;
var HOP_BY_HOP = /* @__PURE__ */ new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "host",
  "content-length",
  "accept-encoding"
]);
var LOOPBACK_HOST = [127, 0, 0, 1].join(".");
var IPV6_LOOPBACK2 = ["", "", "1"].join(":");
var LOOPBACK = /* @__PURE__ */ new Set([LOOPBACK_HOST, "localhost", `[${IPV6_LOOPBACK2}]`, IPV6_LOOPBACK2]);
function upstreamBase(upstream) {
  let url;
  try {
    url = new URL(upstream);
  } catch {
    throw new Error(`Invalid upstream URL: ${upstream}`);
  }
  const ok = url.protocol === "https:" || url.protocol === "http:" && LOOPBACK.has(url.hostname);
  if (!ok) throw new Error("The upstream must use https (plain http is only allowed for loopback addresses)");
  return url.origin + url.pathname.replace(/\/+$/, "");
}
var HttpError = class extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
  status;
};
async function readBody(req, limit) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limit) throw new HttpError(413, `Request body exceeds ${limit} bytes`);
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}
function sendError(res, status, message) {
  if (res.headersSent) {
    res.destroy();
    return;
  }
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify({ type: "error", error: { type: "agent_redact_proxy_error", message } }));
}
async function* readSse(body) {
  const decoder = new TextDecoder();
  let buffer = "";
  const parse = (block) => {
    let event;
    const data = [];
    for (const line of block.split(/\r?\n/)) {
      if (line === "" || line.startsWith(":")) continue;
      const colon = line.indexOf(":");
      const field = colon === -1 ? line : line.slice(0, colon);
      const value = colon === -1 ? "" : line.slice(colon + 1).replace(/^ /, "");
      if (field === "event") event = value;
      else if (field === "data") data.push(value);
    }
    return data.length > 0 ? { event, data: data.join("\n") } : null;
  };
  for await (const chunk of body) {
    buffer += decoder.decode(chunk, { stream: true });
    let match;
    while (match = /\r?\n\r?\n/.exec(buffer)) {
      const ev = parse(buffer.slice(0, match.index));
      buffer = buffer.slice(match.index + match[0].length);
      if (ev) yield ev;
    }
  }
  buffer += decoder.decode();
  const last = parse(buffer);
  if (last) yield last;
}
var RAW = /* @__PURE__ */ Symbol("raw-sse-event");
function formatSse(event, data) {
  const lines = data.split("\n").map((l) => `data: ${l}`);
  return `${event ? `event: ${event}
` : ""}${lines.join("\n")}

`;
}
async function* unmaskSse(body, provider, vault, unmaskToolInputs) {
  let done = false;
  async function* parsed() {
    for await (const ev of readSse(body)) {
      if (provider === "openai" && ev.data.trim() === "[DONE]") {
        done = true;
        return;
      }
      try {
        yield JSON.parse(ev.data);
      } catch {
        yield { [RAW]: ev };
      }
    }
  }
  const adapter = provider === "anthropic" ? unmaskAnthropicStream : unmaskOpenAIStream;
  for await (const item of adapter(parsed(), vault, { unmaskToolInputs })) {
    if (typeof item === "object" && item !== null && RAW in item) {
      const raw = item[RAW];
      yield formatSse(raw.event, raw.data);
      continue;
    }
    const type = provider === "anthropic" && typeof item?.type === "string" ? item.type : void 0;
    yield formatSse(type, JSON.stringify(item));
  }
  if (done) yield "data: [DONE]\n\n";
}
function describeStats(stats) {
  const parts = Object.entries(stats).map(([id, n]) => `${id}:${n}`);
  return parts.length ? ` (${parts.join(", ")})` : "";
}
async function startProxy(options) {
  const provider = options.provider;
  if (provider !== "anthropic" && provider !== "openai") throw new Error('provider must be "anthropic" or "openai"');
  const base = upstreamBase(options.upstream ?? DEFAULT_UPSTREAM[provider]);
  const maxBody = options.maxBodyBytes ?? DEFAULT_MAX_BODY;
  const vault = new Vault();
  const log = options.log ?? (() => {
  });
  const policy = options.unmaskToolInputs;
  const handle = async (req, res) => {
    const path = req.url ?? "/";
    const method = req.method ?? "GET";
    if (!path.startsWith("/")) throw new HttpError(400, "Only origin-form request paths are accepted");
    if (req.headers.origin !== void 0) throw new HttpError(403, "Browser requests are not allowed");
    const host = String(req.headers.host ?? "");
    const hostname = host.startsWith("[") ? host.slice(0, host.indexOf("]") + 1) : host.split(":")[0];
    if (!LOOPBACK.has(hostname.toLowerCase())) throw new HttpError(403, "Requests must address the proxy by its loopback address");
    const raw = await readBody(req, maxBody);
    let body;
    let redacted = 0;
    let stats = {};
    if (raw.length > 0) {
      const encoding = String(req.headers["content-encoding"] ?? "identity").toLowerCase();
      if (encoding !== "identity") throw new HttpError(415, "Compressed request bodies are not supported");
      if (!/^application\/(?:[\w.+-]+\+)?json\b/i.test(String(req.headers["content-type"] ?? ""))) {
        throw new HttpError(415, "Only JSON request bodies are accepted");
      }
      let value;
      try {
        value = JSON.parse(raw.toString("utf8"));
      } catch {
        throw new HttpError(400, "Malformed JSON request body");
      }
      const result = redactDeep(value, { ...options.redactOptions, vault, skipKeys: ["signature"] });
      body = JSON.stringify(result.value);
      redacted = result.totalLeaks;
      stats = result.stats;
    }
    const headers = new Headers();
    for (const [name, value] of Object.entries(req.headers)) {
      if (value === void 0 || HOP_BY_HOP.has(name.toLowerCase())) continue;
      for (const v of Array.isArray(value) ? value : [value]) headers.append(name, v);
    }
    headers.set("accept-encoding", "identity");
    const abort = new AbortController();
    res.on("close", () => abort.abort());
    let upstream;
    try {
      upstream = await fetch(base + path, { method, headers, body, redirect: "manual", signal: abort.signal });
    } catch {
      throw new HttpError(502, "Upstream request failed");
    }
    const outHeaders = {};
    upstream.headers.forEach((value, name) => {
      if (!HOP_BY_HOP.has(name) && name !== "content-encoding" && !name.startsWith("access-control-")) outHeaders[name] = value;
    });
    const contentType = upstream.headers.get("content-type") ?? "";
    log(`${method} ${path.split("?")[0]} -> ${upstream.status} redacted=${redacted}${describeStats(stats)}`);
    if (/text\/event-stream/i.test(contentType) && upstream.body) {
      res.writeHead(upstream.status, outHeaders);
      for await (const chunk of unmaskSse(upstream.body, provider, vault, policy)) {
        if (!res.write(chunk)) await new Promise((r) => res.once("drain", r));
      }
      res.end();
      return;
    }
    if (/json/i.test(contentType)) {
      const text = await upstream.text();
      let out = text;
      try {
        out = JSON.stringify(unmaskDeep(JSON.parse(text), vault, { unmaskToolInputs: policy }));
      } catch {
      }
      res.writeHead(upstream.status, outHeaders);
      res.end(out);
      return;
    }
    res.writeHead(upstream.status, outHeaders);
    if (upstream.body) {
      for await (const chunk of upstream.body) {
        if (!res.write(chunk)) await new Promise((r) => res.once("drain", r));
      }
    }
    res.end();
  };
  const server = http.createServer((req, res) => {
    handle(req, res).catch((err) => {
      const status = err instanceof HttpError ? err.status : 500;
      const message = err instanceof HttpError ? err.message : "Proxy error";
      log(`${req.method ?? "GET"} ${(req.url ?? "/").split("?")[0]} -> ${status} ${message}`);
      if (status === 413) req.resume();
      sendError(res, status, message);
    });
  });
  await new Promise((resolve2, reject) => {
    server.once("error", reject);
    server.listen(options.port ?? 8787, LOOPBACK_HOST, () => {
      server.off("error", reject);
      resolve2();
    });
  });
  const { address, port } = server.address();
  return {
    server,
    vault,
    address,
    port,
    url: `http://${LOOPBACK_HOST}:${port}`,
    close: () => new Promise((resolve2) => {
      server.closeAllConnections();
      server.close(() => resolve2());
    })
  };
}

exports.CONTEXT_PATTERNS = CONTEXT_PATTERNS;
exports.CREDENTIAL_PATTERNS = CREDENTIAL_PATTERNS;
exports.DEFAULT_PATTERNS = DEFAULT_PATTERNS;
exports.PATTERN_MAP = PATTERN_MAP;
exports.PATTERN_PRESETS = PATTERN_PRESETS;
exports.PII_PATTERNS = PII_PATTERNS;
exports.RedactEngine = RedactEngine;
exports.RedactTransformStream = RedactTransformStream;
exports.StreamingUnmasker = StreamingUnmasker;
exports.UnmaskTransformStream = UnmaskTransformStream;
exports.VN_PII_PATTERNS = VN_PII_PATTERNS;
exports.Vault = Vault;
exports.anthropicApiKeyPattern = anthropicApiKeyPattern;
exports.awsAccessKeyPattern = awsAccessKeyPattern;
exports.awsSecretKeyPattern = awsSecretKeyPattern;
exports.azureStorageKeyPattern = azureStorageKeyPattern;
exports.basicAuthUrlPattern = basicAuthUrlPattern;
exports.calculateShannonEntropy = calculateShannonEntropy;
exports.createExpressMiddleware = createExpressMiddleware;
exports.createHighEntropyPattern = createHighEntropyPattern;
exports.createRedactStream = createRedactStream;
exports.createUnmaskStream = createUnmaskStream;
exports.creditCardPattern = creditCardPattern;
exports.databaseUriPattern = databaseUriPattern;
exports.databaseUrlPattern = databaseUrlPattern;
exports.decryptVaultJson = decryptVaultJson;
exports.digitalOceanTokenPattern = digitalOceanTokenPattern;
exports.discordTokenPattern = discordTokenPattern;
exports.dockerConfigAuthPattern = dockerConfigAuthPattern;
exports.dotenvSecretPattern = dotenvSecretPattern;
exports.emailPattern = emailPattern;
exports.encryptVaultJson = encryptVaultJson;
exports.gcpOauthSecretPattern = gcpOauthSecretPattern;
exports.githubTokenPattern = githubTokenPattern;
exports.gitlabTokenPattern = gitlabTokenPattern;
exports.googleApiKeyPattern = googleApiKeyPattern;
exports.groqApiKeyPattern = groqApiKeyPattern;
exports.huggingFaceOrgTokenPattern = huggingFaceOrgTokenPattern;
exports.huggingFaceTokenPattern = huggingFaceTokenPattern;
exports.ipv4Pattern = ipv4Pattern;
exports.ipv6Pattern = ipv6Pattern;
exports.isEncryptedVault = isEncryptedVault;
exports.isHighEntropyToken = isHighEntropyToken;
exports.isPlausibleSecretValue = isPlausibleSecretValue;
exports.isToolUnmaskAllowed = isToolUnmaskAllowed;
exports.jsonStringEscape = jsonStringEscape;
exports.jwtTokenPattern = jwtTokenPattern;
exports.kubernetesSecretPattern = kubernetesSecretPattern;
exports.langsmithApiKeyPattern = langsmithApiKeyPattern;
exports.loadConfig = loadConfig;
exports.mailgunApiKeyPattern = mailgunApiKeyPattern;
exports.netrcPasswordPattern = netrcPasswordPattern;
exports.npmTokenPattern = npmTokenPattern;
exports.npmrcAuthPattern = npmrcAuthPattern;
exports.openaiApiKeyPattern = openaiApiKeyPattern;
exports.openrouterApiKeyPattern = openrouterApiKeyPattern;
exports.parseRegexString = parseRegexString;
exports.perplexityApiKeyPattern = perplexityApiKeyPattern;
exports.phonePattern = phonePattern;
exports.privateKeyPattern = privateKeyPattern;
exports.quotedSecretAssignmentPattern = quotedSecretAssignmentPattern;
exports.redact = redact;
exports.redactDeep = redactDeep;
exports.replicateApiTokenPattern = replicateApiTokenPattern;
exports.resolveCustomPattern = resolveCustomPattern;
exports.resolvePresets = resolvePresets;
exports.sendgridApiKeyPattern = sendgridApiKeyPattern;
exports.slackTokenPattern = slackTokenPattern;
exports.ssnPattern = ssnPattern;
exports.startProxy = startProxy;
exports.stripeKeyPattern = stripeKeyPattern;
exports.supabaseKeyPattern = supabaseKeyPattern;
exports.telegramBotTokenPattern = telegramBotTokenPattern;
exports.twilioAccountSidPattern = twilioAccountSidPattern;
exports.twilioApiKeyPattern = twilioApiKeyPattern;
exports.unmask = unmask;
exports.unmaskAnthropicStream = unmaskAnthropicStream;
exports.unmaskDeep = unmaskDeep;
exports.unmaskOpenAIStream = unmaskOpenAIStream;
exports.unmaskTextStream = unmaskTextStream;
exports.vnBankAccountPattern = vnBankAccountPattern;
exports.vnCitizenIdPattern = vnCitizenIdPattern;
exports.vnIdNumberPattern = vnIdNumberPattern;
exports.vnTaxCodePattern = vnTaxCodePattern;
exports.wrapAgent = wrapAgent;
exports.xaiApiKeyPattern = xaiApiKeyPattern;
//# sourceMappingURL=index.cjs.map
//# sourceMappingURL=index.cjs.map