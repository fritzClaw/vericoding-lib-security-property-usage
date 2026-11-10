# Agent rules

This repo builds an application out of **formally verified Rust** with
[Verus](https://github.com/verus-lang/verus), following the Vericoding
pipeline of [vericoding-kata](https://github.com/fritzClaw/vericoding-kata),
and reuses the verified injection-safety library `lib-security-property/`.
Read `README.md` for the full pipeline. The short version:

```
intent (human, grill) ─▶ spec (agent drafts, HUMAN APPROVES, locked) ─▶ vericode (agent) ─▶ gate (CI)
intents/NNNN-*.md         katas/NNNN-*/src  outside <vc-*>               inside <vc-*>        scripts/verify.sh
```

Every component of the application is one verified crate `katas/NNNN-name/`
("kata"); the command-line binary is a kata with a `src/main.rs` whose I/O lives
in a `// <vc-shell>` region.

## Which stage am I in?

| User asks to…                                | Stage    | Skill / agent             |
|----------------------------------------------|----------|---------------------------|
| explore / clarify a new feature or component | intent   | `grill-intent` (or the user's own `grill-me`) → `intents/NNNN-*.md` from `intents/TEMPLATE.md` |
| write the spec for an intent                 | spec     | `spec-from-intent`, then the `spec-auditor` agent before asking for approval |
| implement / prove a pending kata             | vericode | `vericode`                |
| output with untrusted data in lines / headers / records | intent + spec | `security-property` (on top of the above) |

Never do two stages in one step. In particular, never write the spec and the
proof together, and never lock a spec the human has not approved.

## Security property: apply it by default

Whenever a component **writes or parses line-based text that contains
untrusted data** (file names, user input, records, `NAME:` headers, sections
separated by blank lines) or its output is piped/counted (`| wc -l`, `| grep`,
another parser), the `security-property` skill applies from the intent stage
on: the intent must decide the codec, the document shape and decoding, and
the spec must tie the output to `security_property::unparse_records` /
`unparse_document`. Don't hand-roll escaping, counting or parsing that the
library already proves.

## Hard rules

1. **The spec is trusted, so it is frozen.** Outside `// <vc-helpers>` and
   `// <vc-code>` regions, kata files, `intents/`, and `specs.lock.json` change
   only in the spec stage, with human approval. Do not hand-edit
   `specs.lock.json`. Only `tools/vc.py lock` writes it, after approval.
2. **No escape hatches**: `assume`, `admit`, `#[verifier::external*]`,
   `assume_specification`, `axiom`, `exec_allows_no_decreases_clause`,
   `assume_termination`, `unsafe`, `cfg` tricks. The only allowed `assume` is
   a canonical pending stub as the whole `<vc-code>` body:
   `assume(false); unreached()` (exec fn) or `assume(false);` (proof fn).
3. **A failing proof is information, not an obstacle.** If the spec looks
   wrong or unprovable, stop and report a counterexample. Don't work around it.
4. **`// <vc-shell>` (only in `src/main.rs`) is trusted, unverified code.**
   It may only translate between the OS and the verified core: no sorting,
   filtering, escaping or formatting logic. Flag it for human review.
5. **Vendored code is read-only.** `lib-security-property/`,
   `intents/lib-security-property.md` and `.claude/skills/security-property/`
   are copies of upstream (`vendored.toml`). Change them upstream, then
   `scripts/vendor-sync.sh update lib-security-property <rev>`; CI checks they
   match. Never weaken the library's conditions (C0–C4, F1–F3) to make a
   proof pass.
6. **Done means** `scripts/verify.sh` is green: `vc check` + Verus with
   `--no-cheating` + `cargo test`.

## Commands

```sh
scripts/install-verus.sh && eval "$(scripts/install-verus.sh --print-env)"  # toolchain
tools/vc.py status                         # katas and their state
tools/vc.py new 0001-some-component        # scaffold intent + kata
cargo verus focus -p <crate> -- --expand-errors   # fast proof iteration
scripts/verify.sh [NNNN-name]              # the gate (same as CI)
scripts/vendor-sync.sh check               # vendored libs == upstream
python3 -m unittest discover -s tools      # self-test of the gatekeeper
```

Using the library from a kata: add
`security_property = { path = "../../lib-security-property" }` to the kata's
`[dependencies]` (the manifest is part of the locked spec), and refer to its
spec items by full path (`security_property::unparse_records::<C>(..)`), see
`lib-security-property/templates/spec-link-theorems.md`.

Commit prefixes: `intent(NNNN):`, `spec(NNNN):`, `vericode(NNNN):`, `pipeline:`, `vendor:`.
