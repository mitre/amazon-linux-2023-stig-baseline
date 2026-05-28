# Cross-Vendor STIG Profile Derivation Cookbook

A living runbook for deriving an InSpec STIG profile for a new OS from a
related OS's published profile. Grown incrementally as we run the pilot
(AL2023 from RHEL9) and subsequent derivations (RHEL 10, Debian 12, SLES,
AMZN 2 refresh, Rocky 9).

## Purpose

Capture **what we do**, **why we do it**, and **what goes wrong** so the
next derivation takes a fraction of the time.

## Artifact choice (2026-04-21)

The codified workflow lives as **this runbook**, **local-only for now**
(under `.local/cookbooks/` in the AL2023 repo, gitignored). Options
weighed:

1. **Claude Code skill** — a markdown runbook loaded into Claude
   sessions. Good for the judgment parts. Weak for the mechanical parts
   (Claude re-learns the commands every invocation).
2. **Standalone runbook markdown** (chosen) — canonical doc that
   humans and AI agents both read. Portable across repos. Can be
   adapted into a skill wrapper later without rewriting.
3. **Dedicated `saf generate profile` CLI command** — wraps the
   mechanical layer into a single invocation. Heavier to build;
   reasonable v2.0 goal.

Chosen: runbook-first (#2). The patched `saf generate delta` already
covers the mechanical core. A skill can be a thin wrapper around this
runbook later.

**Externalization is deferred.** The runbook may stay internal
permanently, migrate to `mitre/saf/docs/cookbooks/` after 2u4 lands, or
be published alongside the skill (card 9fh). That decision happens
after the pilot completes — until then, this file is local-only.

## The two layers

**Mechanical** — same steps every derivation:

1. Fetch target-OS XCCDF (published DISA STIG)
2. Pick a "base" InSpec profile (closest-related OS)
3. Generate `profile.json` via `bundle exec inspec json .` in the base
4. Run patched `saf generate delta -X <xccdf> -J <profile.json> -c
   <controls/> -o <out/> -M -T rule -r <report.md>`
5. Inspect the delta report + links output; confirm match rate
6. Commit the delta output as the seed profile
7. Clone/adapt the base profile's kitchen-ec2 harness
8. Run vanilla-EC2 eval; pin a `vanilla.threshold.yml`
9. Iterate: hand-adapt weak-match and no-match controls
10. CI + release

**Judgment** — decisions that require a human (or Claude as stand-in):

- Which base profile is the right ancestor? (AL2023 ← RHEL9 was
  obvious. AMZN 2 refresh ← RHEL7 is trickier. Debian ← Ubuntu vs RHEL
  needs research.)
- Which cherry-picks to fold into the base via a hybrid worktree?
  (AL2023 used V2r7 + GUI/chrony improvements from a feature branch.)
- Which no-match / weak-match controls to hand-adapt vs drop vs N/A?
- When to override a match (e.g. Tier 3 Fuse rescue matched the wrong
  old control)?
- Threshold tuning after vanilla EC2 eval

## Entries

Each entry captures one phase of the pilot, written in present tense as
a runbook, with a "what went wrong" section for post-hoc notes.

### Phase: Pre-flight — verify saf is runnable locally

**Goal:** Make sure `./bin/run generate delta` dispatches to the patched
source code, not a stale compiled `lib/`.

**Why this matters:** saf's oclif config points at `./lib/commands`
(compiled JS). If you edit `src/` and forget to rebuild, or if the
lib/src rewrite mechanism fails silently, you will run an old CLI and
not know it. This wastes hours.

**The mechanism:** oclif-core has a `tsPath` feature that rewrites
`./lib/commands/foo.js` → `./src/commands/foo.ts` when:

1. `NODE_ENV` is `test` or `development`, AND
2. `tsx` (or `ts-node`) is present in `devDependencies`

If either condition is missing, it silently falls back to `lib/`.

**Commands:**

```bash
cd /path/to/saf

# 1. Confirm tsx is installed (devDep).
ls node_modules/tsx/package.json && \
  grep '"version"' node_modules/tsx/package.json | head -1

# 2. Compare lib/ vs src/ mtimes. If src/ is newer, lib/ is stale.
ls -la lib/commands/generate/delta.js src/commands/generate/delta.ts

# 3. Confirm tsPath resolution actually fires and loads src/.
NODE_ENV=development DEBUG='oclif:*' ./bin/run generate delta --help 2>&1 \
  | grep -iE 'ts-path|src/commands|lib/commands' | head -10
```

**Expected debug output signatures** (proof we are running src/, not
lib/):

```
oclif:config:ts-path Determining path for .../saf/lib/commands
oclif:config:ts-path src directory to find: .../saf/src/commands
oclif:config:ts-path Found source directory for .../saf/lib/commands at .../saf/src/commands
oclif:config:@mitre/saf loading IDs from .../saf/src/commands
oclif:config:@mitre/saf (require) .../saf/src/commands/...    ← TypeScript, not JS
```

If you instead see `(require) .../saf/lib/commands/...js`, tsPath is
**not** firing. Check `NODE_ENV` and `node_modules/tsx/` before anything
else.

**What went wrong (history):** The AL2023 pilot lost ~30 minutes to a
stale-`lib/` trap. `@oclif/test`'s `captureOutput` sets `NODE_ENV=test`
automatically, so unit tests were getting src/ resolution — tests
passed. But the integration test path was running against stale `lib/`
because `tsx` was not yet a devDep. Fix: add `tsx` to devDependencies.
Never rely on a pretest rebuild hack; add the transpiler properly.

**When to run this check:**

- Before any real-data eval
- After every `npm install` (devDeps can shift)
- After every branch switch
- Whenever test output looks suspiciously unlike your source

---

### Phase: Real-data delta eval (AL2023 V1R3 vs hybrid RHEL9 V2r7)

**Goal:** Run the patched `saf generate delta` against real cross-vendor
inputs and measure the match rate. This validates the algorithm before
investing in fixture tests, PR prose, or structured output changes.

**Why this is the first real test:** Unit tests (49/49 on Windows 2019
→ 2022 fixture) are a same-vendor scenario. The real question is
cross-vendor: can the 3-tier pipeline (SRG block + CCI tiebreak + Fuse
rescue) map RHEL 9 to Amazon Linux 2023 at the predicted ~98% rate?

**Inputs (verify before running):**

- Target XCCDF (published DISA STIG for new OS): `<published-stig>/U_<OS>_STIG_V<x>R<y>_Manual-xccdf.xml`
- Base profile JSON: `bundle exec inspec json .` from the base profile
  directory, redirected to a local file
- Base profile controls dir: the `controls/` dir of the base profile
  (contains the Ruby control bodies that get carried forward on matches)

**Command** (from the saf repo):

```bash
NODE_ENV=development ./bin/run generate delta \
  -X <path to target OS XCCDF>                           \
  -J <path to base profile.json>                         \
  -c <path to base profile controls/>                    \
  -o <output dir>                                        \
  -M -T rule                                             \
  -r <path to delta report.md>                           \
  2>&1 | tee <stdout log>
```

Flags:
- `-M` — run fuzzy mapping (REQUIRED for our 3-tier pipeline)
- `-T rule` — use Rule IDs (`SV-XXXXX`). Alternative: `group` / `cis` / `version`
- `-o <dir>` — output controls go here
- `-r <file>` — human-readable delta report with per-control diffs

**Expected outputs:**

- `<output>/controls/` — Ruby control files, one per rule in the target
  XCCDF, with matched old-profile bodies carried forward and metadata
  replaced with the new XCCDF values
- `<output>/delta.json` — machine-readable diff (currently
  `ignoreFormattingDiff` + `rawDiff`; TODO: add `links[]`)
- `<report>.md` — human-readable report: matched, new-only, removed,
  per-control diffs
- stdout log — per-control match decisions with `[primary]` /
  `[related]` / "No Match Found" markers + Tier breakdown

**Measuring the results (grep the stdout log):**

```bash
LOG=<stdout-log-path>

echo -n "Primary:            "; grep -c '\[primary\]' "$LOG"
echo -n "Related (1:N):      "; grep -c '\[related\]' "$LOG"
echo -n "No match:           "; grep -c 'No Match Found for:' "$LOG"
echo ""
echo -n "Tier 1 SRG det:     "; grep -c 'SRG deterministic' "$LOG"
echo -n "Tier 2 SRG+CCI:     "; grep -c 'SRG block + CCI tiebreak' "$LOG"
echo -n "Tier 3 Fuse rescue: "; grep -c 'Fuse title-fuzzy' "$LOG"
echo ""
echo -n "Potential Mismatch: "; grep -c 'Potential Mismatch' "$LOG"
```

**Interpreting the output:**

- **Primary + Related = total mapped controls.** This is the "did we
  find an ancestor for this new rule" rate. Goal ≥98%.
- **Primary only** is the stricter "we found a 1:1 match" rate.
- **No Match** means: the target SRG has zero controls in the base
  profile AND Fuse fallback (against normalized titles) also failed.
  These are usually **genuine new requirements** for the target OS —
  not algorithm failures.
- **Potential Mismatch** appears on matches where the CCI Jaccard is
  low (rough heuristic: <50%). The algorithm picked something in the
  SRG block, but content overlap is weak. **Human review required** —
  these go on the ao0 hand-adapt queue.
- **Tier breakdown** tells you where your matches are coming from:
  - Tier 1 (SRG det) = cleanest, 1:1 SRG block matches
  - Tier 2 (SRG + CCI) = multi-candidate resolution within SRG
  - Tier 3 (Fuse) = cross-SRG rescue; weakest; usually rare

**AL2023 pilot results (2026-04-21):**

| Metric | Count | % of 187 |
|---|---|---|
| Primary matches | 173 | **92.5%** |
| Related (1:N) | 13 | 7.0% |
| No match | 1 | 0.5% |
| **Total mapped** | **186** | **99.5%** |

Tier breakdown: Tier 1 = 29, Tier 2 = 147, Tier 3 = 10.

Potential Mismatch flags: 11 (low CCI Jaccard: 0%, 13%, 24%, 33%×8).

Before-patch baseline (from recovery doc): 62/187 primary (33%). So
this is a **~3× improvement** in primary match rate and a 99.5% total
mapping rate.

**The 1 genuine no-match** (for the PR body):
- `SV-274030` / `AZLX-23-001090`: "Amazon Linux 2023 must manage
  excess capacity, bandwidth, or other redundancy to limit the effects
  of information flooding types of denial-of-service (DoS) attacks"
- SRG `SRG-OS-000142-GPOS-00071` — zero RHEL 9 coverage
- This is a novel AL2023 DoS-resilience requirement. Correct algorithm
  behavior: do not fabricate a match when there is no ancestor.

**What to do with the flagged and unmatched controls:**

- Record the 11 "Potential Mismatch" rule IDs + the 1 no-match rule ID
  on the AL2023 hand-adapt epic (card ao0). These are the controls
  that get hand-written or hand-reviewed after the delta run lands.

**What went wrong / lessons for the cookbook:**

- *None this run.* Delta ran clean first try on real cross-vendor
  inputs after the Phase-1 pre-flight verification. That pre-flight is
  load-bearing — skipping it is how you end up running stale `lib/`
  and not knowing it.

**Open issue surfaced by this phase:**

- `delta.json` only contains `ignoreFormattingDiff` + `rawDiff`. No
  structured `links[]` record. This means the 11 Potential Mismatch
  flags and the 1 no-match are only accessible by grepping stdout.
  Next phase addresses this (card 2u4 punch list item 1).
  - Phase: Cross-vendor integration test fixture — DONE 2026-04-21
    - **Shipped:** `test/sample_data/delta-matching/rhel9-base-mini-profile.json`
      (9 controls) + `al2023-target-mini-profile.json` (11 rules) +
      `test/utils/__tests__/cross-vendor-integration.test.ts`
      (10 assertions). Commit `175033bb`.
    - **What the fixture covers:** every tier, the 1:N split behavior,
      a CCI-Jaccard=0 `potentialMismatch` primary (pinned as the only
      flag — regression guard on the threshold), a Tier-3 Fuse rescue
      across different SRGs, and a genuine no-match for a novel
      requirement. 10/11 mapped = 90.9%, which locks in the >=90%
      promise.
    - **Fixture design rule** for future cross-vendor fixtures: pick
      IDs + CCIs + titles that exercise each tier with minimal
      overlap. The test should PIN the expected old<->new mapping
      for at least every Tier-1 primary, the Tier-3 rescue, and
      every `potentialMismatch` case — so future algorithm tweaks
      surface as diff on known IDs, not aggregate count drift.
    - **Parse-level test, not command-level:** calls
      `applyRequirementFirstPipeline` directly on loaded JSON. The
      full-CLI e2e is blocked on the fixture-`inspec.yml` +
      `cinc-auditor` gap that's captured as a future saf follow-up.
  - Phase: `delta.json` structured links output — DONE 2026-04-21
    - **Shipped:** `delta.json` now carries `links: LinkRecord[]`
      alongside `ignoreFormattingDiff` + `rawDiff`. One record per
      target-profile control with (`oldId`, `newId`, `matchMethod`,
      `confidence`, `relationship`, `srg`, `potentialMismatch`).
    - **Two saf commits:**
      - `28924133` feat(delta): add potentialMismatch flag to LinkRecord
      - `52dfe85b` feat(delta): persist per-control links into delta.json
    - **Testing lesson (captured here so future work doesn't re-learn
      it):** the existing Windows fixture integration test asserts
      only stdout strings, not `delta.json` content, because the
      fixture directory is missing `inspec.yml`. The `-M -c` code path
      hits an `fs.copyFile` for that file well before `delta.json` is
      written, and then requires `cinc-auditor` for a profile-JSON
      regen step. Neither is available in the test env. We covered the
      payload contract via unit tests on the pure
      `buildDeltaJsonPayload({diff, links})` helper and verified the
      full wired path on real data (AL2023 V1R3 × RHEL 9 V2r7) — 187
      links landed, aggregates matched the log-scraped numbers. A
      proper e2e fixture (mini `inspec.yml` + a cinc-auditor-less
      code path) is a saf follow-up, not a blocker for this PR.
    - **Downstream consumers now have a clean input shape:**
      `jq '[.links[] | select(.potentialMismatch)]'` for the review
      queue; `jq '[.links[] | .matchMethod] | group_by(.) |
      map({method: .[0], count: length})'` for PR-body tier numbers;
      `jq '.links[] | select(.relationship == "no-match")'` for novel
      requirements with no ancestor.
  - Phase: saf upstream PR
  - Phase: Commit derived AL2023 controls (card j64) — DONE 2026-04-21
    - **Import strategy:** three focused commits, not one bulk dump.
      Each stage has a distinct rollback story and a readable diff.
      - `cedd8bf` — 187 controls from `/tmp/<run>/controls/` →
        `controls/`. Commit message lists the 11 flagged IDs + the
        1 novel no-match ID so reviewers know what to look at.
      - `c48fd32` — 7 custom InSpec resources from hybrid base →
        `libraries/`. Commit message captures the generalization
        status (`linux_updates.rb` already multi-vendor; `gui.rb`
        may need an `'amazon'` family case; other five unchecked).
      - Local only: `.local/delta-provenance/` holds the raw
        `delta.json`, human-readable `delta-report.md`, and
        `stdout.log` from the run (gitignored — not shipped with
        the profile, but available to any reviewer who clones and
        wants the full audit trail).
    - **Local-saf gotcha:** this step was gated on card 2u4 (upstream
      PR) in the original plan. In practice, the patched saf on the
      local `feat/delta-requirement-first-matching` branch is
      functional; we proceeded without waiting for upstream merge.
      If the saf PR review forces algorithm changes, re-run delta and
      commit a "regenerate from saf vX" second import on this repo.
      Card 2u4 still has punch list items 4 (PR body) + 5
      (build-unblock decision) open.
    - **Why separate commits:** a reviewer can accept the controls
      import (1) without also accepting the libraries (2) if the
      latter needs further adaptation. Splitting also keeps diff
      review sane — 187 new files is enough in one commit without
      also mixing supporting code changes.
  - Phase: Clone RHEL9 kitchen-ec2 harness (card oji)
  - Phase: Hand-adapt weak-match controls (card ao0)
    - Reference: `<INSPEC_AST_PARSER>` Ruby gem
      (`<PATH>/ — parses
      InSpec profiles via <AST_LIB> into model objects; enables
      surgical edits via `<TREE_REWRITER>` that preserve formatting and
      comments. The right tool for bulk AST-driven modifications to
      the generated control bodies when the delta's carried-forward
      describe blocks need adaptation for the target OS.
  - Phase: Vanilla EC2 eval + threshold pin (card dtf)
  - Phase: CI (card dws)
  - Phase: Release + retrospective for next derivation
