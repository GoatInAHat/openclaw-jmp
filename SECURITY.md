# Security Policy

## Reporting a vulnerability

Please use [GitHub private vulnerability reporting](https://github.com/GoatInAHat/openclaw-jmp/security/advisories/new). Do not include credentials, phone numbers, message contents, or exploit details in a public issue.

## Operational boundary

SMS sender identity can be spoofed. This project quarantines all inbound senders by default and must not be treated as cryptographic authentication. Keep credentials outside the repository with mode `0600`, protect message/audit logs, and use least-privilege model API keys.

Only the latest release is supported with security fixes.
