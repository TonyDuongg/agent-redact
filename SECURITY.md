# Security Policy 🛡️

`agent-redact` is a security-focused project designed to prevent credential leaks and protect user privacy in LLM and Agentic workflows. We take security vulnerabilities seriously.

---

## 🔒 Supported Versions

We actively provide security patches for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

---

## 🚨 Reporting a Vulnerability

If you discover a security vulnerability, false negative on a critical token, or regular expression denial of service (ReDoS) condition in `agent-redact`, please **DO NOT** open a public issue.

Instead, please report it via one of the following methods:

1. **GitHub Private Vulnerability Reporting**:
   Go to the [Security Advisory tab](https://github.com/TonyDuongg/agent-redact/security/advisories/new) on our GitHub repository and click **Report a vulnerability**.
2. **Direct Email**:
   Email the maintainer at `nguyenhaiduong052005@gmail.com` with the subject `[SECURITY] agent-redact Vulnerability Report`.

### What to Include in Your Report
* Description of the vulnerability or regex pattern bypass.
* Sample sanitized payload demonstrating the bypass.
* Expected behavior vs. actual behavior.
* Impact assessment on LLMs or agentic workflows.

---

## ⏱️ Response SLA

* **Initial Response**: Within 48 hours of receipt.
* **Triage & Patch**: Within 5-7 business days depending on severity.
* **Public Disclosure**: Coordinated after an official patch release has been published to npm.
