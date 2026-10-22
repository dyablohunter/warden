# Contributing to Warden

Thanks for helping! Warden runs as root on people's servers, so we care a lot about three things:
**safety, cheapness, and boring reliability.** This guide explains how to contribute without
compromising any of them.

## Dev setup

```bash
git clone https://github.com/dyablohunter/warden.git && cd warden
python3 -m unittest discover -s tests -t .      # ~90 tests, a few seconds, any OS, no root, no network
```

That's it: there are no dependencies to install. Python ≥ 3.10.

To try it for real **without changing anything**, use an Ubuntu box or VM (WSL works too):

```bash
cp .env.example .env            # add an LLM key
sudo env WARDEN_STATE_DIR=/tmp/wd python3 -m warden --observe check
sudo env WARDEN_STATE_DIR=/tmp/wd python3 -m warden --observe run security_pulse --force
sudo env WARDEN_STATE_DIR=/tmp/wd python3 -m warden --observe daemon     # Ctrl-C to stop
```

`--observe` forces read-only autonomy, and `WARDEN_STATE_DIR` keeps your experiments out of `/var/lib/warden`.

## Design principles (please read before a big PR)

1. **Standard library only.** No third-party packages. This keeps the supply chain of a root daemon tiny.
2. **Cheap detection first, LLM second.** Detection reads `/proc`, `/sys`, the journal stream or log tails. Avoid subprocesses on the sentinel's hot path. The LLM is only woken by gates, triggers and notable events, so ask yourself: "does this wake the LLM more often than needed?"
3. **Safety invariants are sacred.** The denylist, the read-only classifier, protected IPs, config validation with rollback, untrusted-data wrapping and the audit log are listed in [CLAUDE.md](CLAUDE.md#safety-invariants-do-not-weaken-without-a-very-good-reason). PRs that weaken them need an issue and a discussion first.
4. **Bounded everything.** Anything stored is rotated, and anything injected into a prompt has a cap. If you add a table, add it to `Store.prune`. If you add prompt content, give it a budget.
5. **Pure, tested parsers.** Parsing and decision logic are plain functions with unit tests that run on any OS.
6. **Match the surrounding code.** Same naming, comment density and idioms. Small, focused PRs are reviewed fastest.

## Adding a detector

| You want to detect… | Where | Test in |
|---|---|---|
| brute force on another service | add a rule to `AUTH_RULES` in `warden/sentinel.py` (journald identifiers and/or log files, a regex with `(?P<ip>…)`) | `tests/test_sentinel.py::test_auth_rules` |
| a web attack pattern | `EXPLOIT` / `SCANNER_UA` / `handle_web` in `warden/sentinel.py` | `tests/test_sentinel.py` |
| a new kernel/host metric | `Sampler` in `warden/metrics.py` (+ `METRICS` in `triggers.py`) | `tests/test_metrics.py` |
| a condition worth waking the agent by default | `default_triggers()` in `warden/triggers.py` | `tests/test_safety.py::test_default_triggers_valid` |
| something a routine should review | a collector in `DEFAULT_ROUTINES` (`warden/routines.py`) with the right gate; bump `DEFAULTS_VERSION` in `daemon.py` | `tests/test_routines.py` |

Collectors and command triggers must pass `safety.is_read_only`, because they run without LLM review.

## Adding an LLM provider

- **OpenAI-compatible endpoint:** add a preset to `PROVIDER_PRESETS` in `warden/config.py`. That's usually the whole PR.
- **Anything else:** implement `Provider.chat()` (see `warden/llm/anthropic.py`). Convert to and from the canonical OpenAI-style message list, return usage as `{"in", "out", "cached"}`, and add conversion tests.

Then run `python3 -m warden test-llm` against the real API and paste the output in your PR.

## PR checklist

- [ ] `python3 -m unittest discover -s tests -t .` passes
- [ ] new parsing/decision logic has tests
- [ ] no new dependencies; no subprocess on the sentinel hot path
- [ ] new settings are in `config.Settings` **and** `.env.example`
- [ ] new stored data is rotated; new prompt content is capped
- [ ] docs updated (README / CLAUDE.md) if behaviour changed
- [ ] if you touched safety code: explain the threat model in the PR description

## Reporting false positives

These reports are gold. Please include the exact log line or command output (redact IPs and hostnames if you like), what Warden did, and what it should have done.

## Security issues

Please **don't** open a public issue for vulnerabilities (denylist bypasses, prompt injections that lead to actions, secret leaks). See [SECURITY.md](SECURITY.md).

## Code of conduct

Be kind, assume good intent, and keep discussions technical. Everyone was new once.
