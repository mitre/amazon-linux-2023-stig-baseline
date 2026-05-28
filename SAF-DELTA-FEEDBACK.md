# `saf generate delta` — Feedback from the AL2023 Pilot

Short overview. The detailed analysis + every cited claim live in [`saf-delta-cli-improvement-themes.md`](./saf-delta-cli-improvement-themes.md) and the artifacts under [`delta-provenance/`](./delta-provenance/).

## TL;DR

The AL2023 profile was derived from RHEL9 V2R7 on 2026-04-21 via `saf generate delta -M`. **~30+ controls subsequently required hand-fixing for delta-induced bugs.** Most of those bugs fall into a handful of repeatable classes; each class is a concrete improvement target for the delta CLI. With the highest-leverage improvements landed, future derivations (RHEL 10, Debian 12, SLES, AMZN 2 refresh, Rocky 9) would see a fraction of the hand-fix burden.

## What's in this branch for review

| File | What it's for |
|------|---------------|
| `SAF-DELTA-FEEDBACK.md` | This file — short overview |
| `saf-delta-cli-improvement-themes.md` | Detailed analysis: 6 bug classes, evidence, proposed CLI improvements with code sketches |
| `delta-provenance/al2023-v1r3-from-rhel9-v2r7.stdout.log` | Original delta-run stdout (815 KB) — per-control match decisions with Jaccard score |
| `delta-provenance/al2023-v1r3-from-rhel9-v2r7.delta.json` | Structured delta output (1.5 MB) — full mapping table + added/removed/changed lists |
| `delta-provenance/al2023-v1r3-from-rhel9-v2r7.delta-report.md` | Human-readable delta report (519 KB) |
| `delta-provenance/cross-vendor-profile-derivation-cookbook.md` | Methodology runbook |

## The bug classes (six categories)

1. **Template assertion drift (N→1 mapping leakage)** — When multiple target controls map to one source, the source's specific assertions leak into all targets. Example: the audit `-S all` cluster (6 controls templated from SV-274112). Fixed in `c6a459d`.
2. **Multi-file content miss (narrow-source carry-forward)** — When the target STIG check text says to grep both `.conf` + `.conf.d/*.conf` but the source only reads main, delta carries forward the narrow check. Example: pwquality `.conf.d/` cluster (6 controls). Fixed in `81dbb7e`.
3. **Single-control body misplacement (wrong-sibling mapping)** — Code from a different control's body lands under this control's title. Example: SV-274107 (title says `disk_full_action`, body checked `$DefaultNetstreamDriver`). Will's commits `ef90f3e`, `627c868`, `8663364`, `9719cde`, `e3d943d` and session commit `e832ba1` all addressed instances.
4. **Residual vendor strings** — `describe` block headlines, `only_if` reason messages, comments still say "RHEL 9" after delta. Will's commits `6578b3e`, `5d7ffed` cleaned these up.
5. **Test shuffling** — Test bodies landed in the wrong file altogether. Will's commit `5c8c6f5`.
6. **`find` flag bugs** — Generated `find` invocations missing `-xdev` and mishandling array inputs. Will's commit `2af10df`.

## Proposed CLI improvements (priority order)

1. **N→1 mapping detection + annotation** — Warn or annotate output when multiple targets map to one source.
2. **STIG-text-aware post-mapping validation** — After mapping, flag carried-over assertions whose terms don't appear in the target's STIG check text.
3. **Drop-file pattern detection + scaffold** — Recognize `X.conf X.conf.d/*.conf` patterns in STIG check text and generate the iteration template.
4. **Vendor-string sweep across all string-context sites** — Extend the current rewrite pass beyond titles/desc to describe headlines, only_if reasons, skip messages, comments, failure_message strings.
5. **Confidence-gated output annotation** — Mark controls with `# DELTA-LOW-CONFIDENCE` when Jaccard < some threshold.

Phase A (items 1, 4, 5) is small code changes to the existing pipeline. Phase B (item 2) requires parsing STIG check text post-mapping. Phase C (item 3) requires synthesizing the iteration scaffold. **Phase A alone would have eliminated the majority of bugs in this pilot.**

## What I'd find useful to discuss

- Whether to file these as beads cards on the saf-cli board (I can draft).
- Whether the detailed analysis doc + the provenance under `delta-provenance/` is the right artifact format, or if you'd rather it live as a separate `mitre/saf` issue with links back here.
- The cookbook in `delta-provenance/cross-vendor-profile-derivation-cookbook.md` was set up to grow with each derivation. Worth promoting somewhere more visible (e.g. `mitre/saf/docs/cookbooks/`) once the AL2023 pilot lands?
