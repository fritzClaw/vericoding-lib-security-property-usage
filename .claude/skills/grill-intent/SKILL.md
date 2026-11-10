---
name: grill-intent
description: Stage 1 of the vericoding pipeline. Interview the human relentlessly about a new feature or component until every decision is made, then write intents/NNNN-*.md from intents/TEMPLATE.md. Use when the user describes something new to build, says "grill me", "new kata", "new component", or an intent has open questions. (If the user has their own grill-me skill, either one is fine; the output format is the same.)
---

# Grill an intent

The spec is the weak link of vericoding: a proof against a wrong spec is
worthless. This stage makes the human's intent precise *before* anything is
formalised. You ask; the human decides. You never decide a semantic question
yourself.

## Steps

1. **Scaffold** if needed: `tools/vc.py new NNNN-short-name` (next free
   number, see `tools/vc.py status`). This creates `intents/NNNN-short-name.md`
   from the template and an empty kata crate.
2. **Interview**, a few questions at a time, walking the decision tree
   depth-first until every branch is resolved. Always cover:
   - inputs, outputs, Rust types, ownership; what the function is *for*;
   - edge cases: empty input, duplicates, ties, maximum sizes, overflow,
     invalid / non-UTF-8 data, errors (what is returned, what is impossible);
   - determinism and uniqueness: is the output pinned down, or is any of
     several answers fine?
   - what is verified core vs trusted shell (argv, files, stdout);
   - **untrusted data in text output** (names, user input, records, headers,
     blank-line sections, output piped to `wc -l`/`grep`/a parser): if yes,
     also load the `security-property` skill and paste
     `lib-security-property/templates/intent-rows.md` into the intent; decide
     codec, records vs grouped document, and whether decoding is needed.
   Offer a recommended answer with each question, but record what the human
   chose.
3. **Write the intent** (`intents/NNNN-*.md`):
   - one Decisions row per resolved question;
   - Examples with the right answer **and a plausible wrong answer** the spec
     must reject;
   - Properties (uniqueness, permutation, round trip, exact count, …);
   - Not verified: what Verus won't prove here and how it is covered instead;
   - Open questions: must be **empty** before stage 2.
4. Set `status: grilled`, show the human the file, and commit as
   `intent(NNNN): <title>` once they agree.

## Rules

- No spec, no code in this stage.
- Don't resolve ambiguity by guessing. An unanswered question stays under
  "Open questions", and the spec stage can't start.
- Keep the intent in the human's language; formulas belong in the spec.
