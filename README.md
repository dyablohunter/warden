<div align="center">

# 🛡️ Warden

### An autonomous AI sysadmin that guards your Ubuntu server 24/7, and only thinks when it has to.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)
![Ubuntu](https://img.shields.io/badge/Ubuntu-26.04%20LTS-E95420?logo=ubuntu&logoColor=white)
![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)
![LLM](https://img.shields.io/badge/LLM-DeepSeek%20%7C%20OpenAI%20%7C%20Claude%20%7C%20Gemini%20%7C%20Ollama-8A2BE2)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-ff69b4.svg)](CONTRIBUTING.md)

**Stops brute force and floods in seconds · investigates and fixes problems · follows them up until they're solved · emails you what happened**

[Quick start](#-quick-start) · [How it works](#-how-it-works) · [What it catches](#-what-it-catches) · [Cost](#-what-it-costs) · [Safety](#-safety-model) · [Contributing](#-contributing)

</div>

---

## Why Warden?

Most monitoring tools tell you something is wrong at 3 a.m. and leave the rest to you. Warden handles the 3 a.m. part itself. It reads the logs, works out the cause, fixes what is safe to fix, keeps watching until the fix holds, and writes you a short report.

It does this without paying an LLM to stare at your server all day.

- 🧠 **Reflexes first, reasoning second.** A deterministic sentinel reads kernel counters and streams logs (~4 ms per check) and bans attackers on its own. The LLM is woken only when something needs judgement, so a quiet server costs **zero LLM calls** most of the time.
- 🔁 **It follows through.** Unsolved problems become incidents with a next step. Follow-ups back off from 30 minutes to a day, and watchers tied to an incident wake it the moment something changes. When it needs a decision from you, it says exactly what to do.
- 🧩 **It adapts to your server.** On first start it profiles the host and arms watchers for *your* services. Over time it mutes noise it has already reviewed and retunes its own routines.
- 🔌 **Bring your own model.** DeepSeek by default; OpenAI, Claude, Gemini, Mistral, Groq, OpenRouter, Ollama or any OpenAI-compatible endpoint, with an optional fallback. You switch with one line.
- 🪶 **Zero dependencies.** Pure Python standard library, using the `python3` that ships with Ubuntu. Nothing to `pip install` into a root daemon.
- 🔒 **Guarded root.** A command denylist, autonomy levels, config validation with automatic rollback, protected IPs, prompt-injection-aware prompts, and an audit log of every action.

## 🚀 Quick start

```bash
git clone https://github.com/dyablohunter/warden.git && cd warden
cp .env.example .env && nano .env      # LLM API key, EMAIL_TO, SMTP_*, WARDEN_ALLOWLIST
sudo ./install.sh --extras             # --extras adds lynis, debsums, needrestart, smartmontools
```

The installer:
1. installs `nftables`
2. copies the code to `/opt/warden` and your config to `/etc/warden/warden.env` (mode 600)
3. **allowlists the IP you're installing from**
4. checks the LLM connection and starts `warden.service`

Warden then onboards itself and emails you an introduction to your own server.

```bash
warden status                    # what it's watching, incidents, bans, token use
warden ask "why is load high?"   # give it a task
journalctl -u warden -f          # watch it think
```

> **Tip:** start with `WARDEN_AUTONOMY=observe` for a few days. Warden investigates and reports but can't change anything until you trust it.

## 🧭 How it works

```
 ┌──────────────────────────── warden.service (root, Restart=always) ────────────────────────────┐
 │  JOURNAL STREAM (real time)          SENTINEL (every 10s, /proc only)      MAIN LOOP (sleeps)  │
 │  ssh / postgres / mysql / mail       SYN cookies, listen drops, conntrack, 1. notable events   │
 │  auth failures ──► ban               pps, Mbps, disk fill ETA...           2. incident follow- │
 │  log triggers ──► event              per-IP floods ──► ban                    ups (backoff)    │
 │  new error signatures ──► db         web: floods, scanners, credential     3. onboarding (1x)  │
 │                                        stuffing, exploits ──► ban          4. gated routines   │
 │                                      anomalies vs learned baseline ─┐            │             │
 │  warden event "..." ─────────────── triggers ─────────────────── wake            ▼             │
 │                                                                           LLM AGENT + tools    │
 │  nftables `inet warden` · expiring bans · per-source SYN/conn/ICMP limits (shell, files, bans, │
 │  + optional Cloudflare edge bans                                          incidents, triggers) │
 └───────────────────────────────────────────────────────────────────────┬───────────────────────┘
                                                                         ▼
                                                        email: alerts + weekly report
```

**Routines collect data without the LLM.** Each data source has a *gate*. The LLM is called only when a gate fires, and then it sees a **diff** against what it last reviewed, not a full dump.

| Routine | Collects every | Wakes the LLM when… |
|---|---|---|
| `security_pulse` | 15 min | new privilege use, account changes, new listeners, exposed DB ports, new network-active processes or outbound ports |
| `health_pulse` | 30 min | an error message **never seen before** on this host appears, or failed units change |
| `system_sweep` | 24 h | security updates, reboot-required, expiring certs, time sync, containers, oversized logs |
| `integrity_sweep` | 24 h | accounts, sudoers, SSH keys, cron, units, SUID files, critical hashes, `/tmp` executables change |
| `weekly_review` | 7 d | always: hardening audit, self-tuning, and **your weekly report** |

**Triggers** are deterministic watchers the agent creates for itself, for example "wake me if Postgres connections > 80", "if nginx logs 50 upstream timeouts in 5 minutes", or "if this file changes again". Kinds: `metric`, `log` (real time), `command`, `service`, `port`, `file`. Your own scripts can wake it too: `warden event --severity high "backup failed"`.

## 🎯 What it catches

| Threat | How it's detected (cheaply) | What happens |
|---|---|---|
| SYN / connection / ICMP floods | per-source kernel limits; SYN cookies, accept-queue drops, conntrack fill | dropped in-kernel; floods banned; the agent can tighten limits live |
| Distributed floods | new connections/s, packets/s, Mbps and HTTP rates vs a **learned baseline** | anomaly wakes the agent with the top talkers |
| Volumetric DDoS | inbound bandwidth vs link speed | critical alert telling you to enable upstream mitigation |
| SSH / database / mail brute force | sshd, PostgreSQL, MySQL, Postfix, Dovecot failures, streamed live | escalating bans |
| Web / API abuse | request floods, 4xx storms, **credential stuffing**, exploit probes, scanner user agents (sqlmap, nikto, nuclei…) in nginx/apache/Caddy logs | ban on the host, and **at the Cloudflare edge** if configured |
| Disk trouble | usage, **time-until-full** from the fill rate, I/O saturation, read-only remounts, kernel I/O errors | the agent finds the writer or failing disk |
| Compromise / persistence | changes to `passwd`, `sudoers`, root keys, `ld.so.preload`; new network processes (miners, reverse shells); deleted binaries; `/tmp` executables | the agent investigates |
| Health | new error signatures, failed units, OOM kills, memory, load | the agent investigates and fixes |

### ☁️ Cloudflare-aware

Warden works the same whether some sites, all sites, or none sit behind Cloudflare:
- **Never bans Cloudflare's addresses.** It refreshes Cloudflare's published ranges weekly and exempts them from per-source limits.
- **Tells you when real-IP logging is misconfigured.** If your logs record Cloudflare's IPs instead of visitors', it alerts you.
- **Bans at the edge.** With `CLOUDFLARE_API_TOKEN` set, web attackers are blocked at Cloudflare, because a host firewall can't stop traffic that arrives through Cloudflare. Edge rules are removed automatically when the ban ends.
- **Flags origin bypass.** It notices when your origin is reachable without going through Cloudflare.

## 💸 What it costs

Measured on Ubuntu 26.04 with `deepseek-chat`. "Effective" counts cached prompt tokens at 10%, which is roughly how providers bill them.

| Run | Input tokens (cached) | Effective |
|---|---|---|
| Routine where nothing changed | 0 | **0** |
| `health_pulse` with a new error | 31k (26k) | ~8k |
| `security_pulse` with a change | 60k (53k) | ~14k |
| Event triage | 27k (21k) | ~9k |
| Onboarding (once) | 528k (484k) | ~105k |

What keeps it cheap:
- The system prompt is static, so the provider caches it (86–95% cache hits measured).
- Old tool output in a run is trimmed in batches, and long runs are checkpointed into a summary.
- Memory, incident history and per-run data are hard-capped.
- `WARDEN_DAILY_TOKEN_BUDGET` pauses scheduled routines if you ever hit it. Attack handling never pauses.

Everything Warden stores is **rotated automatically**: events, audit trail, emails, error signatures, incident notes, config backups. Hard row caps mean even a sustained attack can't bloat the database.

## 🔒 Safety model

| Guardrail | What it does |
|---|---|
| Autonomy levels | `observe` (read-only; it can still tune its own watchers) → `contain` (+ bans) → `full` (+ system changes) |
| Denylist, always on | blocks disk wipes, `rm -rf /`, `curl \| sh`, flushing firewalls, stopping SSH or Warden, reboots (unless allowed), and reading secrets (`.env` files, private keys, `/etc/shadow`) |
| Read-only classifier | everything that runs without LLM review (collectors, command triggers) must be provably read-only |
| Protected IPs | never banned: your allowlist, the host's own addresses, recent successful SSH logins, Cloudflare, and private IPs in web logs (usually your proxy) |
| Config edits | backed up, written atomically, validated (`sshd -t`, `nginx -t`, `visudo -c`, `nft -c`…) and **rolled back** on failure |
| Prompt-injection aware | log lines, URLs and user agents are wrapped as untrusted data, and the model is told never to follow instructions found in them |
| Audit trail | every tool call is recorded (`warden log`) |

**Honest limits:** a host can't absorb a flood that saturates its uplink. Put serious targets behind upstream protection (your provider's DDoS filtering, or Cloudflare). Warden will detect the saturation and tell you. Warden is a powerful root process; read the code, start in `observe` mode, and use it at your own risk.

## ⚙️ Configuration

Everything lives in `/etc/warden/warden.env`. See [`.env.example`](.env.example) for every knob.

```ini
LLM_PROVIDER=deepseek             # deepseek | openai | anthropic | gemini | mistral | groq | openrouter | ollama | custom
DEEPSEEK_API_KEY=sk-...
# LLM_MODEL=...  LLM_BASE_URL=...  LLM_FALLBACK_PROVIDER=ollama

WARDEN_AUTONOMY=observe           # observe | contain | full
WARDEN_ALLOWLIST="203.0.113.7"    # your IPs: never banned
EMAIL_TO=you@example.com          # alerts + weekly report
SMTP_HOST=smtp.example.com
CLOUDFLARE_API_TOKEN=...          # optional: edge bans
```

<details>
<summary><b>CLI reference</b></summary>

```
warden status                     routines, triggers, incidents, bans, token use, recent LLM runs
warden onboard                    (re)run the host profile
warden run <routine> [--force]    run a routine now (--force calls the LLM even if nothing changed)
warden ask "..."                  give the agent an instruction
warden event [--severity S] "..." wake the daemon with an event
warden incidents [ID] [--all]     incidents / full history        warden resolve ID "note"
warden bans | ban IP | unban IP
warden routines [-v] [enable|disable NAME]
warden triggers [-v] [enable|disable|delete NAME]
warden log -n 100                 audit log of everything the agent did
warden check | test-llm | test-email
```
</details>

## 🗺️ Roadmap

Ideas we'd love help with. Each one is a good place to start contributing:

- [ ] **More notification channels:** Slack, Discord, Telegram, ntfy, generic webhooks
- [ ] **More auth "jails":** Gitea/Forgejo, Grafana, WordPress, Nextcloud, vsftpd, Asterisk
- [ ] **More distros:** Debian, Ubuntu 24.04 LTS, Rocky/Alma (firewalld)
- [ ] **Packaging:** a `.deb` / PPA, so it's `apt install warden`
- [ ] **Prometheus exporter** for the sentinel's metrics
- [ ] **A small read-only web/TUI dashboard**
- [ ] **XDP/eBPF fast path** for line-rate drops
- [ ] **Fleet mode:** several hosts, one brain, shared ban intelligence
- [ ] **Agent eval harness:** replay recorded incidents and score the agent's decisions across models
- [ ] **Local-model tuning:** prompts and tool schemas that work well with small Ollama models

## 🤝 Contributing

**Warden is young and contributions are very welcome**, whether you're a sysadmin with war stories, a security person who wants to break it, or a Python developer who likes clean, dependency-free code.

- 🐛 **Found a bug or a false positive?** [Open an issue](https://github.com/dyablohunter/warden/issues) with the log line or scenario.
- 🧪 **Have a detection idea?** Most detectors are a regex or a counter plus a test. See [CONTRIBUTING.md](CONTRIBUTING.md#adding-a-detector).
- 🔌 **Use a provider we don't?** Adding one is usually a preset line.
- 🔐 **Found a way to make Warden do something dangerous**, such as a denylist bypass or a prompt injection that works? Please report it privately; see [SECURITY.md](SECURITY.md). These are the most valuable reports of all.
- 📝 **Docs, examples, translations of the weekly report**: all welcome.

Read [CONTRIBUTING.md](CONTRIBUTING.md) for the dev setup and design principles. The short version: stdlib only, cheap detection first, never weaken a safety invariant without discussion, and every parser comes with a test. `python3 -m unittest discover -s tests -t .` runs the full suite in a few seconds on any OS, with no root and no network.

If Warden saves you a night's sleep, **⭐ star the repo** and tell a fellow sysadmin.

## 📄 License

[MIT](LICENSE) © 2026 dyablohunter. Architecture notes for contributors (and AI coding assistants) are in [CLAUDE.md](CLAUDE.md).
