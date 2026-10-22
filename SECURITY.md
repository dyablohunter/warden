# Security policy

Warden runs as root and acts on LLM output, so security reports are the most valuable contributions we get.

## Reporting a vulnerability

Please report privately via **GitHub → Security → [Report a vulnerability](https://github.com/dyablohunter/warden/security/advisories/new)**.
Do not open a public issue.

Include:
- what an attacker controls (a log line, an HTTP path or user agent, a username, a file on disk…)
- what Warden ends up doing (the command run, the file written, the ban or unban, the data sent to the LLM)
- the version or commit, and a minimal reproduction if possible

We aim to acknowledge reports within a few days and to fix confirmed issues before disclosing them.

## In scope

- **Denylist / read-only classifier bypasses:** a command that `safety.check_command` or `safety.is_read_only` wrongly allows.
- **Prompt injection that leads to action:** attacker-controlled data (logs, HTTP requests, usernames, process names) that makes the agent run commands, unban IPs, change configs, or email or exfiltrate data.
- **Secret exposure:** ways for the agent to read the Warden env file, private keys, password hashes or application `.env` files and send them to the LLM provider.
- **Self-DoS:** ways to get Warden to ban protected addresses (the operator, Cloudflare, its own IPs) or to lock the operator out.
- **Resource exhaustion:** inputs that make Warden's storage, memory or LLM spend grow without bound.

## Out of scope

- Attacks that require root on the host already.
- The LLM giving a wrong *opinion* in a report. Please file those as normal issues; they're still very welcome.
