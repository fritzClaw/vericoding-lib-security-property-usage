# vericoding-lib-security-property-usage

An application built by **vericoding**: an AI agent writes Rust code *together
with a machine-checked proof* that the code meets a specification, and
[Verus](https://github.com/verus-lang/verus) checks the proof. The human spends
their attention on *what* should be true (intent and spec), not on reading
every line of code.

The pipeline, gate and agent skills come from
[fritzClaw/vericoding-kata](https://github.com/fritzClaw/vericoding-kata), and
the verified injection-safety library
[`lib-security-property`](lib-security-property/README.md) is vendored from
there. Any component that writes or parses line-based text containing
untrusted data gets **record safety** (data can't add or remove a delimiter,
so `| wc -l` counts exactly) and **structure safety** (data can't forge a
header or separator: parse(unparse(x)) = x) *for free*, by tying its output to
the library's proved unparser.

> **Invariant:** the agent can never change what it is proving. Specs are
> derived from a human-grilled intent, approved by a human, hash-locked, and
> every escape hatch that makes the verifier trust instead of check is
> rejected.

## The pipeline

```
 ┌────────────┐ grill-intent  ┌────────────┐  spec-from-intent  ┌──────────────┐   vericode   ┌──────────────┐
 │   idea     │ ────────────▶ │  INTENT    │ ─────────────────▶ │  SPEC        │ ───────────▶ │  VERIFIED    │
 └────────────┘  (human +     │ intents/   │  (agent drafts,    │ frozen part  │  (agent,     │  <vc-*>      │
                  agent)      │ NNNN-*.md  │   spec-auditor,    │ of katas/... │  iterates    │  regions     │
                              └────────────┘   HUMAN approves,  │ + spec tests │  with Verus) │  filled in   │
                                     ▲          vc.py lock)     └──────────────┘              └──────────────┘
                                     │                                  ▲                             │
                 security-property skill: codec, records/document,      └─── spec bug? back to intent ┘
                 link to security_property::unparse_* (when untrusted
                 data ends up in line-based output)
 gate on every push/PR:  scripts/verify.sh  =  vc.py check  +  Verus (--no-cheating)  +  cargo test
                         scripts/vendor-sync.sh check  (vendored library == upstream)
```

| Stage | Artifact | Who writes | Who approves | Changes require |
|---|---|---|---|---|
| 1. Intent | `intents/NNNN-name.md` (from `intents/TEMPLATE.md`) | human + agent (`grill-intent` skill) | human | code-owner review |
| 2. Spec | everything in `katas/NNNN-name/` **outside** `<vc-*>` regions: spec fns, contracts, spec tests | agent (`spec-from-intent` skill, `spec-auditor` agent) | human, then `tools/vc.py lock` | code-owner review (lock changes) |
| 3. Vericode | `// <vc-helpers>` and `// <vc-code>` regions | agent (`vericode` skill) | **Verus**, via CI | green CI only |
| 3b. Shell | `// <vc-shell>` region in `src/main.rs`: trusted, unverified I/O glue | agent (`vericode` skill) | **human review** of the PR | review |

The application is a set of katas: each component is one verified crate
`katas/NNNN-name/`; the command-line binary is a kata with a `src/main.rs`
that keeps all logic in the verified core and only does argv/files/stdout in
its `<vc-shell>`. Details of each stage, the region markers and the gate are in
the upstream [README](https://github.com/fritzClaw/vericoding-kata#readme) and
in `CLAUDE.md`.

## Quick start

```sh
scripts/install-verus.sh                    # pinned Verus release + Rust toolchain
eval "$(scripts/install-verus.sh --print-env)"
scripts/verify.sh                           # the gate (same as CI)
tools/vc.py status

# a new component
tools/vc.py new 0001-some-component         # scaffolds intent + crate
#   1. "grill me on 0001"           (grill-intent)      → intents/0001-some-component.md
#   2. "spec kata 0001"             (spec-from-intent)  → spec-auditor → you approve → tools/vc.py lock
#   3. "vericode kata 0001"         (vericode)          → scripts/verify.sh green
```

In Claude Code cloud sessions the committed SessionStart hook installs Verus
automatically (see [docs/claude-code.md](docs/claude-code.md)).

## Using `lib-security-property` in a component

1. **Intent:** if the component prints or parses names, records, `NAME:`
   headers or blank-line sections containing untrusted data, paste
   [`templates/intent-rows.md`](lib-security-property/templates/intent-rows.md)
   into the intent and decide codec (`BackslashEscape`, a custom escape family,
   or an arbitrary table), records vs grouped document, and decoding.
2. **Spec:** depend on the library from the kata's manifest
   ```toml
   [dependencies]
   vstd.workspace = true
   security_property = { path = "../../lib-security-property" }
   ```
   and make the output *provably equal* to
   `security_property::unparse_records::<C>` / `unparse_document::<C>` (call
   the exec unparser, or prove a link theorem:
   [`templates/spec-link-theorems.md`](lib-security-property/templates/spec-link-theorems.md)).
3. **Vericode:** use `theorem_record_count`, `theorem_records_injective`,
   `theorem_document_injective`, `count_delims`, `decode_records`,
   `decode_document`; never re-implement them.

## The vendored library

`lib-security-property/`, its intent `intents/lib-security-property.md`, its
spec-lock entry in `specs.lock.json`, and the agent skill
`.claude/skills/security-property/` are exact copies of the upstream commit in
[`vendored.toml`](vendored.toml). The library goes through the same gate as
every kata here (spec lock, escape-hatch scan, Verus `--no-cheating`).

```sh
scripts/vendor-sync.sh check                                   # CI runs this too
scripts/vendor-sync.sh update lib-security-property <commit>   # re-vendor
git diff                                                       # review the upstream change
tools/vc.py lock lib-security-property                         # after review
scripts/vendor-sync.sh check && scripts/verify.sh
```

## Layout

```
intents/                 human intent per component (grill output) + TEMPLATE.md
katas/NNNN-name/         one verified crate per application component
lib-security-property/   vendored verified library (crate `security_property`)
specs.lock.json          hashes of approved specs + intents (written only by vc.py lock)
vendored.toml            upstream commit of every vendored library
tools/vc.py              lock / check / status / new   (+ tools/test_vc.py self-tests)
scripts/verify.sh        the gate (local == CI)
scripts/vendor-sync.sh   check / update vendored libraries
scripts/install-verus.sh pinned Verus release installer
scripts/claude-session-start.sh   SessionStart hook for Claude Code cloud sessions
verus-toolchain.env      VERUS_VERSION / VSTD_VERSION / RUST_TOOLCHAIN pins
.claude/settings.json    hook + permissions (lock is ask, lock file and vendored files are deny)
.claude/skills/          grill-intent, spec-from-intent, vericode, security-property
.claude/agents/          spec-auditor
.github/                 CI (verify, release), CODEOWNERS, PR template, Dependabot
docs/claude-code.md      what the Claude Code setup does
```

## CI

- **`verify`** (every push to `main` and every PR): gatekeeper self-tests,
  `scripts/verify.sh`, a **⚠️ Spec change** banner on PRs touching
  `specs.lock.json`, `intents/` or `vendored.toml`, and a separate job
  `vendored libraries match upstream`.
- **`release`** (tag `vX.Y.Z` on `main`, or manual run with `version`): runs the
  gate on Apple Silicon (`macos-15`), builds every binary target, ad-hoc signs
  and publishes `<repo>-vX.Y.Z-aarch64-apple-darwin.tar.gz` + `SHA256SUMS`.
  PRs touching the workflow or `scripts/` do a dry run; while the workspace has
  no binary yet, the dry run stops after the gate.

## Repository settings you need to turn on

The pipeline is only as strong as its merge rules. On GitHub, protect `main`:

- Require the status checks `verify / spec lock + Verus + tests` and
  `verify / vendored libraries match upstream`.
- Require pull request review, with **"Require review from Code Owners"**.
  Then any PR that touches `specs.lock.json`, `intents/`, the vendored library
  or the gate itself needs code-owner approval. Pure vericode PRs only need a
  green build.

## Upgrading Verus

The pin must stay equal to upstream's, because the vendored library is
verified against it (a different `vstd` won't link). Bump upstream first, then
copy `verus-toolchain.env`, `vstd` in `Cargo.toml` and the channel in
`rust-toolchain.toml` (`vc check` fails until all three agree), re-vendor the
library and run `scripts/verify.sh`.

## License

See [LICENSE](LICENSE).
