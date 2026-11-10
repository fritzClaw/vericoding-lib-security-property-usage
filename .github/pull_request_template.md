## Stage

- [ ] **Intent**: new/changed `intents/NNNN-*.md` (grill-me output)
- [ ] **Spec**: Verus spec + spec tests, `specs.lock.json` re-locked
- [ ] **Vericode**: implementation + proofs only (`<vc-*>` regions), no lock change
- [ ] **Pipeline**: tooling / CI / toolchain
- [ ] **Vendor**: `scripts/vendor-sync.sh update …` of a vendored library (`vendored.toml`)

## Kata(s)

<!-- e.g. 0001-list-entries -->

## Security property

<!-- Does this kata write or parse lines/records/headers containing untrusted
     data? If yes: which codec, records or grouped document, and which link
     theorem / contract ties the output to security_property::unparse_*?
     If no: say why. -->

## Trusted shell

<!-- Vericode PRs touching `// <vc-shell>`: list the regions for review. -->

## Spec review (Spec stage only)

<!-- Map every Decision / Example / Property in the intent to the spec clause
     or spec test that captures it. Anything not captured goes under
     "Not verified" in the intent. -->

| Intent item | Spec clause / spec test |
|---|---|
| D1 | |

## Checklist

- [ ] `scripts/verify.sh` passes locally
- [ ] Vericode PRs: `specs.lock.json` and `intents/` are untouched
- [ ] Spec PRs: `spec-auditor` verdict attached
- [ ] Vendored files are untouched (or changed only via `scripts/vendor-sync.sh`)
