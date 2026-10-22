# CLAUDE.md — Warden

Warden is an autonomous, 24/7 sysadmin & security agent for **Ubuntu 26.04 LTS** servers. It runs as a
root systemd service. A deterministic **sentinel** watches the host continuously and cheaply (kernel
counters, a journald stream, log tails) and blocks attacks by itself. The **LLM agent** is woken only
when something needs judgement. It then investigates and fixes the problem through guarded tools,
tracks unresolved problems as incidents until they are fixed, and emails the operator.

**Core principle: cheap deterministic detection decides *when* to think; the LLM decides *what it
means and what to do*.** A quiet server costs a few LLM runs per day, not one per scan.

## Design decisions (and why)

| Decision | Choice | Why |
|---|---|---|
| Language | **Python 3, stdlib only** | Ships with Ubuntu (3.14 on 26.04); no pip/venv; subprocess, sqlite3, smtplib, ssl, ipaddress built in. No third-party code in a root daemon. |
| Process model | One systemd service (`Restart=always`), 3 threads | Needs persistent state, sub-second reflexes and a self-modifying schedule, which cron can't provide. Threads: **sentinel** (10s tick), **journal** (`journalctl -f` stream), **main loop** (sleeps until the next job). |
| Telemetry | `/proc` + `/sys` reads (`metrics.Sampler`) | ~4 ms per tick on a live host, with no subprocesses on the hot path (only `systemctl --failed`, cached 60s). One snapshot feeds triggers, anomaly detection and routine context. |
| Logs | One streaming `journalctl -f -o json` process + rotation-safe file tailer | Real-time bans, resumable cursor, nothing re-scanned. Web and DB log files are tailed by offset. |
| LLM gating | Routines collect without the LLM; per-collector **gates** decide whether to call it | Data collection is cheap; LLM review of unchanged data is waste. |
| Attack response | Sentinel bans immediately; routine bans are `info` events (no LLM) | An LLM is too slow and costly for floods. It is woken only for **notable** events: attack waves, baseline anomalies, new-IP logins, refused or failed bans, private-IP web abuse, triggers, external events. |
| Firewall | Own nftables table `inet warden` (priority -10, policy accept) | Coexists with ufw/Docker. Drops only banned sources and per-source floods. Bans live in set timeouts, so they expire even if Warden dies. |
| LLM | Provider-agnostic (`warden/llm/`) | Canonical messages = OpenAI chat format. `openai_compat` covers DeepSeek, OpenAI, OpenRouter, Groq, Mistral, Gemini, Ollama and vLLM; `anthropic` covers Claude. Optional `LLM_FALLBACK_*`. |
| Prompt caching | **Static system prompt**; volatile data in the task message; batched trimming | DeepSeek and OpenAI cache identical prefixes automatically; Anthropic gets `cache_control` breakpoints. Measured cache hit rate 86–95%. |
| Context | Always-on aging + checkpoint summaries + capped cross-run inputs | Every step resends the conversation; nothing injected or stored may grow without bound (see lifecycle section). |
| State | SQLite `/var/lib/warden/warden.db` (WAL) | Routines (+ suppressions, last reviewed outputs), triggers, incidents + notes, events, bans, error signatures, audit log, runs (+ cached tokens), memory, kv. |

## Cadence: how often do we actually need each job?

We asked this for every job, and answered it with the question "when could the answer have changed,
and how fast must we react?"

| Job | Runs | LLM called when | Rationale |
|---|---|---|---|
| Sentinel tick | 10s | never | Brute force and floods need seconds. Reading `/proc` costs ~4 ms. |
| Journal stream | continuous | never (it raises events) | SSH/DB/mail auth failures are banned on arrival; log triggers fire in real time. |
| Triggers | own `interval_s` (≥15s); log triggers in real time | when they fire | Acute conditions such as disk full, OOM, SYN cookies, conntrack, service down and integrity files. |
| Anomaly detector | every tick | when a rate exceeds its learned baseline | Catches *distributed* floods that stay under every per-IP limit. |
| `security_pulse` | 15 min | privilege use, account changes, listeners, exposed DB ports, network processes or outbound ports **changed** | Data is cheap and changes are rare. 15 min bounds the latency of human-speed intrusions. |
| `health_pulse` | 30 min | **new** error signature, or the failed-unit set changed | Acute health is covered by triggers. The LLM only sees errors never seen before on this host. |
| `system_sweep` | 24 h | security updates, reboot-required, cert expiry < 21d, time sync, containers, upgrade errors changed | Updates and certs move daily. I/O errors and reboot-required are covered by triggers. |
| `integrity_sweep` | 24 h | any change in accounts, sudoers, keys, cron, units, SUID files, hashes, `/tmp` executables | Persistence changes are rare and diffable. Critical files also have real-time file triggers. |
| `weekly_review` | 7 d | always (ungated) | Hardening audit, self-tuning and the operator's weekly report, merged into one run. |
| Onboarding | once | always | Profiles the host, arms service-specific triggers and suppresses known noise up front. This makes later runs cheaper. |
| Event triage | on notable events | debounced 45s; ≥5 min apart unless high/critical | Batches related events. |
| Incident follow-up | backoff 30m → 1h → 2h … 24h | when due, or immediately when a linked trigger fires | Triggers replace polling. `needs_human` stops follow-ups; `INCIDENT_MAX_CHECKS` (12) hands it to the operator. |

Measured on Ubuntu 26.04 with deepseek-chat (tokens in, of which cached):

| Run | Tokens in (cached) | Steps |
|---|---|---|
| Onboarding (once) | 528k (484k cached) | 30 (1 checkpoint) |
| `health_pulse` with a signal | 31k (26k) | 4 |
| `security_pulse` with a signal | 60k (53k) | 6 |
| Triage | 27k (21k) | 3 |
| Any quiet routine | 0 | 0 |

## Cheap detection per threat

| Area | Signal (all cheap) | Response |
|---|---|---|
| Network / DoS | `/proc/net/snmp`+`netstat`: SyncookiesSent, ListenDrops, PassiveOpens, Retrans, UDP/ICMP rates; `/proc/net/dev` pps/Mbps vs link speed; conntrack fill; per-IP established and SYN_RECV from `/proc/net/tcp` | nft per-source SYN/conn/ICMP limits (kernel); per-IP conn-flood ban; triggers `syn-flood`, `listen-overflow`, `conntrack-full`, `uplink-saturated`; EWMA anomalies; attack waves; agent can tighten nft limits live |
| Web / API | access-log tail (combined or JSON): per-IP rate, 4xx storms, 401/403 on auth paths (credential stuffing), exploit-path regex, scanner user agents; global req/5xx rates | ban (never private IPs, which are probably your proxy, unless `WEB_BAN_PRIVATE`); `http_*_ps` anomalies |
| Database | PostgreSQL/MySQL auth failures (journal or `/var/log/{postgresql,mysql}`), `port_conns:<port>` vs max connections, DB/cache ports listening on non-loopback (`@exposed_services`) | ban brute force; onboarding arms connection triggers; exposure wakes `security_pulse` |
| Mail | postfix SASL / dovecot auth failures | ban |
| SSH | sshd + sshd-session messages, weighted (fail, invalid user, preauth, scanners) | ban; first login from a new IP → notable event; successful-login IPs become trusted |
| Disk | statvfs on writable real mounts; fill **ETA** (least-squares slope over 30 min); `/proc/diskstats` busy %; read-only remounts; kernel I/O errors (log trigger) | triggers `disk-full`, `disk-filling-fast`, `inodes-full`, `disk-io-saturated`, `fs-readonly`, `kernel-io-errors` |
| Host compromise | integrity file triggers (`passwd`, `sudoers`, root keys, `ld.so.preload`, `sshd_config`), new network processes / outbound ports (miners, reverse shells), deleted binaries, `/tmp` executables | wake LLM via gates/triggers |

## Layout

```
warden/
  __main__.py      python -m warden → cli.main
  cli.py           daemon | status | run [--force] | onboard | ask | event | incidents | resolve | bans | ban | unban | routines | triggers | log | test-llm | test-email | check
  config.py        .env parsing, Settings, provider presets, TUNABLE bounds (NFT_TUNABLES reload the firewall)
  daemon.py        Warden (wiring, job runners, reporting, budget) + Daemon (main loop, onboarding, routing, backoff)
  sentinel.py      reflex layer: SSH/DB/mail auth rules, web detectors, conn floods, anomalies, attack waves
  metrics.py       /proc parsers, Sampler (gauges + rates + disk ETA), TcpTable, AnomalyDetector (EWMA)
  journal.py       JournalStream (journalctl -f), FileTailer, ErrorTracker (normalised error signatures)
  triggers.py      trigger kinds, validation, evaluation, real-time log triggers, built-in defaults
  routines.py      built-in routines, gates, {since} windows, diffs, suppressions, internal @collectors
  agent.py         LLM tool loop, per-kind step limits, token cap, context compaction, cached-token accounting
  prompts.py       static system prompt + situation block + per-task prompts (data wrapped as untrusted)
  tools.py         tools exposed to the LLM, gated by autonomy + safety, all audited
  safety.py        command denylist, read-only classifier, secret-path guard, config validators
  firewall.py      nftables ruleset + BanManager (protected IPs, escalating durations, edge bans, edge expiry)
  proxies.py       trusted proxies (Cloudflare ranges, weekly refresh) + CloudflareEdge (IP Access Rules API)
  notify.py        SMTP mailer with throttle + digest
  db.py            SQLite store (+ column migrations)
  util.py          subprocess runner (process-group kill), truncation, time helpers
  llm/             base.py, openai_compat.py, anthropic.py, __init__.py (factory + fallback)
systemd/warden.service · install.sh · uninstall.sh · tests/ (stdlib unittest)
```

## Context & data lifecycle (nothing grows without bound)

**Within a run** (`agent.py`): every step resends the conversation, so it is kept small all the time.
- **Aging:** only the last `FRESH_ROUNDS` (2) tool rounds keep full output. Older outputs are trimmed to `AGED_KEEP` (600) chars. Trimming is batched (once `AGE_TRIGGER`, 16k chars, of stale output builds up) so the prompt prefix changes rarely and keeps hitting the provider cache.
- **Checkpoint:** if the conversation still exceeds `CONTEXT_CHAR_BUDGET` (60k chars), the model writes a working summary and the conversation restarts as system + task + summary (max 3 per run; a deterministic fallback summary is used if the model fails).
- **Final step:** on the last allowed step (or at 90% of the token cap) only `finish` is offered and other calls are refused, so every run ends with a real report.
- Tool output is capped at 8k chars; `AGENT_MAX_TOKENS_PER_RUN` caps a run; per-kind step limits apply.

**Across runs** (`prompts.py`, `tools.py`): every run starts fresh from the static system prompt plus a capped situation block and task data.
- Memory: ≤ 40 keys, ≤ 6000 chars total (enforced by `remember`), ≤ 4000 chars injected, most recent first. The weekly review consolidates it.
- Incidents: ≤ 10 in the situation block. A follow-up sees the running `summary` (rewritten by the agent via `update_incident(summary=…)`) plus the last 6 notes.
- Routine data: ≤ 30k chars per prompt (signals first, context gets the rest). Triage shows ≤ 40 events at ≤ 400 chars each, plus counts.

**Stored data** (`db.prune` + `Daemon.housekeeping`, hourly): retention per table, then hard row caps (newest kept).

| Data | Rotation |
|---|---|
| events | info 7d, all 30d, cap 100k |
| actions, runs | `WARDEN_RETENTION_DAYS` (90), caps 50k / 20k |
| emails | 30d, cap 5k |
| error signatures | unseen 30d, cap 20k |
| incident notes | ≤ 50 per incident; resolved incidents deleted after 180d |
| bans | inactive 90d |
| trusted IPs | 365d |
| expired suppressions, disabled non-builtin triggers | 30d |
| config backups | 30d and ≤ `WARDEN_BACKUP_MAX_MB` |
| SQLite file | WAL checkpoint(TRUNCATE) daily, plus incremental vacuum when >20% of pages are free |

Warden's own logs go to journald (rotated by journald). The host's logs are the agent's job: `system_sweep` flags files over 500MB, and onboarding/weekly review check journald `SystemMaxUse` and logrotate.

## Reverse proxies / Cloudflare

`TRUSTED_PROXIES=cloudflare` (default) loads Cloudflare's ranges (built-in list, refreshed weekly from cloudflare.com, last good list kept in kv). Behaviour:
- **Never banned:** `BanManager.protected_reason` refuses Cloudflare addresses.
- **Flood limits:** their ranges are added to the nft allow sets, so they skip per-source limits; the sentinel's per-IP connection-flood check skips them too.
- **Proxy IPs in web logs** mean real-IP logging is misconfigured: the line is not attributed, and a once-a-day notable event `web_logs_show_proxy_ips` fires.
- **Edge bans:** web bans pass `edge=True`. With `CLOUDFLARE_API_TOKEN` + `CLOUDFLARE_ACCOUNT_ID|ZONE_ID`, the attacker is also blocked via IP Access Rules (rule id stored in `bans.edge_rule`; `expire_edge()` deletes rules when bans end, because Cloudflare rules don't expire). The agent's `block_ip` has `edge=true`.
- **`@proxy_status`** reports, in stable categories: whether traffic is behind the proxy (yes/partial/no), whether logs show real IPs, whether edge bans are configured, and whether the origin can be reached directly. Onboarding and weekly_review act on it.

## Gates, suppressions, triggers: how the agent tunes its own signal

- Collector gates: `changed` (the LLM gets a **diff** against the last reviewed output), `nonempty` (pair with `--since {since}` = last review time, so windows have no gaps and no overlap), `context` (shown only if something else fired). `gated=false` makes a routine always run the LLM.
- `last_run` and `last_outputs` advance only on a quiet run or a *successful* LLM review. A failed run re-covers the same window.
- `suppress_signal` adds narrow, expiring regexes per routine/collector. This is how benign recurring lines stop waking the LLM.
- Triggers: kinds `metric` (snapshot), `log` (stream), `command`, `service` (oneshot units fire only on `failed`), `port`, `file`. They take `consecutive`, `cooldown_s`, `once` and `expires_in_minutes`. With an `incident_id`, firing or recovery wakes that incident directly instead of a generic triage.
- Self-monitoring tools (routines, triggers, suppressions, thresholds) are allowed in **every** autonomy mode because they never touch the host. Bans need `contain`; system changes need `full`.
- `DEFAULTS_VERSION` in daemon.py: bump it when built-in routines/triggers change. Built-ins still owned by `seed` are upgraded; agent-modified ones are left alone.

## Safety invariants: do not weaken without a very good reason

- Every tool call is written to the `actions` audit table.
- The `safety.check_command` denylist applies in **all** modes:
  - disk wipes and `rm -rf /`
  - reboot/shutdown unless `WARDEN_ALLOW_REBOOT` (token-based detection, so words inside quoted patterns don't false-positive)
  - `curl | sh`, flushing firewalls
  - stopping or disabling ssh or warden
  - reading secrets: Warden's env file, app `.env` files, private keys, shadow
- Never ban protected IPs: loopback, `WARDEN_ALLOWLIST`, the host's own addresses, recent successful SSH logins. Web detectors never ban private IPs unless `WEB_BAN_PRIVATE=true`.
- `write_file` and `replace_in_file` back up, write atomically, validate known configs (`sshd -t`, `visudo -c`, `nginx -t`, `nft -c`, …) and roll back on failure.
- Collectors and command triggers run without LLM review, so they must classify as read-only (`{since}` is substituted before the check).
- Log, HTTP and user-agent data is attacker-controlled. Prompts wrap it in `<collected_data>`, and the system prompt forbids following instructions found inside. Keep it that way.
- Never commit `.env`. The agent must never be able to read `/etc/warden/warden.env`.

## Conventions

- Stdlib only. Python ≥ 3.10 (`from __future__ import annotations`), tested on 3.12 (Windows) and 3.14 (Ubuntu 26.04).
- Keep parsers pure (`parse_*`, `service_verdict`, `signature`, `make_diff`…) so they're unit-testable anywhere.
- No subprocess on the sentinel hot path; prefer `/proc`, `/sys` and the journal stream.
- Shell commands go through `util.run` (bash `-o pipefail`, `LC_ALL=C.UTF-8`, timeout, process-group kill).
- New knobs go in `config.Settings` and `.env.example`. Agent-tunable ones also go in `TUNABLE` with bounds.
- Severity everywhere: `info < low < medium < high < critical`. `info` events never wake the LLM.

## Commands

```bash
python -m unittest discover -s tests -t .     # 92 tests, any OS, no root/network
sudo ./install.sh --extras                    # install on Ubuntu
warden status | onboard | run security_pulse [--force] | ask "..." | event "..." | test-llm | test-email
journalctl -u warden -f
# live read-only check from a checkout on an Ubuntu box (uses ./.env):
sudo env WARDEN_STATE_DIR=/tmp/wd python3 -m warden --observe onboard
```

## Adding an LLM provider

If it speaks the OpenAI chat-completions API, add a preset to `config.PROVIDER_PRESETS` (or use
`LLM_PROVIDER=custom` + `LLM_BASE_URL`). Otherwise implement `llm.base.Provider.chat()`, converting
to and from the canonical message list. Report usage as `{"in", "out", "cached"}` and register the
provider in `llm/__init__.py`.
