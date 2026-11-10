# Claude Code setup

Everything below is committed, so it is active in every Claude Code session
(local or cloud) that opens this repo.

## Skills (`.claude/skills/`)

| Skill | Stage | Source |
|---|---|---|
| `grill-intent` | 1. intent: interview, write `intents/NNNN-*.md` | this repo (your own user-level `grill-me` works too) |
| `spec-from-intent` | 2. spec: draft, audit, get approval, lock | upstream vericoding-kata (adapted) |
| `vericode` | 3. implement + prove inside `<vc-*>` regions | upstream vericoding-kata |
| `security-property` | intent + spec, for untrusted data in line-based output | **vendored** from `lib-security-property/skill/SKILL.md` |

## Agents (`.claude/agents/`)

- `spec-auditor`: read-only, adversarial review of a drafted spec against its
  intent. `spec-from-intent` runs it before asking you to approve; you can also
  run it on any PR that touches `specs.lock.json` or `intents/`.

## SessionStart hook + permissions (`.claude/settings.json`)

- **Hook**: `scripts/claude-session-start.sh` runs only when
  `CLAUDE_CODE_REMOTE=true` (cloud sessions). It is synchronous and idempotent:
  the first session downloads the pinned Verus release (~1–2 min), later ones
  take about a second. It also puts `verus`/`cargo-verus` on `PATH`.
- **allow**: the routine, read-only or gate commands (`scripts/verify.sh`,
  `tools/vc.py status|check|new`, `cargo verus verify|focus`, `cargo test`, …).
- **ask**: `tools/vc.py lock` and `scripts/vendor-sync.sh update`, so locking a
  spec or re-vendoring a library always needs your click.
- **deny**: hand edits of `specs.lock.json`, `vendored.toml` and the vendored
  library, its intent and its skill.

## Cloud environment

The cloud environment needs network access to `github.com` (Verus release
assets, and the upstream repo for `scripts/vendor-sync.sh`),
`static.rust-lang.org` (rustup) and crates.io.
