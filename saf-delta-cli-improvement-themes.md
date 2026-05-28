# `saf generate delta` — Improvement Themes from the AL2023 Pilot

Captured during the May 2026 sweep of PR `fix/update-for-release`. The AL2023 profile was derived from RHEL9 V2R7 via `saf generate delta -M` on 2026-04-21. ~30+ controls subsequently required hand-fixing for delta-induced bugs. This document captures the broken-condition patterns and proposes targeted improvements to the delta CLI.

---

## Provenance summary

The full delta-run artifacts are checked into this branch under `delta-provenance/`. Browsing them directly is the fastest way to understand the bug classes below — every claim in this document is traceable to a specific entry in these files.

| File (in `delta-provenance/`) | Size | Contents |
|------|------|----------|
| `al2023-v1r3-from-rhel9-v2r7.stdout.log` | 815 KB | Full stdout, per-control match decisions with method + Jaccard score |
| `al2023-v1r3-from-rhel9-v2r7.delta.json` | 1.5 MB | Structured output: added / removed / renamed / changed control IDs; full mapping table |
| `al2023-v1r3-from-rhel9-v2r7.delta-report.md` | 519 KB | Human-readable delta report (mapControls JSON + per-control diff) |
| `cross-vendor-profile-derivation-cookbook.md` | 16 KB | Methodology runbook intended to grow with each derivation |

### The exact invocation

```bash
saf generate delta \
  -X <PATH>/U_Amazon_Linux_2023_STIG_V1R3_Manual-xccdf.xml \
  -J /tmp/rhel9-hybrid-profile.json \
  -c <PATH>/rhel9-v2r7-plus-gui/controls \
  -o /tmp/al2023-patched-run2 \
  -r /tmp/al2023-patched-report2.md \
  -T rule \
  -M
```

Flags:
- `-X` — target XCCDF (AL2023 V1R3 from DISA)
- `-J` — InSpec profile JSON summary of the **base** (RHEL9 V2R7 hybrid worktree, generated via `bundle exec inspec json .`)
- `-c` — base profile's `controls/` directory
- `-o` / `-r` — output directory and report file
- `-T rule` — ID type = rule (SV-ID semantics)
- `-M` — runMapControls (the fuzzy mapping pipeline; this is where most bugs originate)

### Match-method distribution (186 controls)

```
77  SRG block + CCI tiebreak  Jaccard=100%  [primary]   — clean
30  SRG block + CCI tiebreak  Jaccard=50%   [primary]   — soft
 7  SRG block + CCI tiebreak  Jaccard=67%   [primary]
 6  SRG block + CCI tiebreak  Jaccard=92%   [primary]
 6  SRG block + CCI tiebreak  Jaccard=100%  [related]
 6  Fuse title-fuzzy          (no SRG overlap)          — fallback
 5  SRG block + CCI tiebreak  Jaccard=33%   [primary]
 3  SRG block + CCI tiebreak  Jaccard=50%   [related]
 …
```

The bugs we surfaced clustered in the **lower-confidence matches** and in cases where multiple targets mapped to one source.

---

## Broken-condition patterns

Each pattern is a class of bug observed across multiple controls, traceable to a specific behavior of the `-M` mapControls pipeline.

### 1. Template assertion drift (N→1 mapping leakage)

**Symptom.** When N target controls map to one source control (because they share SRG-block + CCI), the source's specific assertions get carried into all N targets — even when their individual STIG check texts differ.

**Canonical example: the audit `-S all` cluster.** SV-274093, 274095, 274098, 274099, 274100, 274105 all inherited `expect(auditctl_output).to match(/-S\s+all\b/)` from SV-274112 (sudo). SV-274112's STIG check text legitimately shows `-S all`. The other six STIGs do not. A properly hardened system fails all six controls as false-findings.

**Fix in branch:** commit `c6a459d` removes the stray assertion across all six.

**Delta CLI improvement:** when mapControls maps N targets to one source, either:
- Warn the user and require explicit acknowledgment, OR
- After mapping, re-validate that the source's assertions reference things mentioned in *each target's* individual STIG check text, OR
- Mark the output controls with a `# DELTA-N-TO-1-FROM=SV-XXX` comment so a reviewer can re-check.

### 2. Multi-file content miss (narrow-source carry-forward)

**Symptom.** When the target STIG check text explicitly says to grep BOTH a main config file AND a drop-file directory (e.g. `/etc/X.conf /etc/X.conf.d/*.conf`), but the RHEL9 source control only reads the main file, the delta carries forward the narrow check. Result: false-findings on systems using drop-files.

**Canonical example: the pwquality `.conf.d/` miss cluster.** SV-274133, 274134, 274135, 274137, 274138, 274140 — STIG check text says `grep <setting> /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf`; code only read main file.

**Fix in branch:** commit `81dbb7e` rewrites all six to iterate both locations using the same pattern as SV-274136 / SV-274139 (which were already correct).

**Delta CLI improvement:** when the target STIG check text mentions `X.conf X.conf.d/*.conf` (or similar `.d/` pattern), generate an iteration scaffold automatically:

```ruby
<setting>_files = ['/etc/X.conf'] + Dir.glob('/etc/X.conf.d/*.conf')

values_found = <setting>_files.flat_map do |path|
  next [] unless file(path).exist?
  parsed = parse_config_file(path).params
  parsed.key?(<setting>) ? [[path, parsed[<setting>]]] : []
end

bad_values = values_found.reject { |_path, v| <condition> }

describe "<setting>" do
  it 'should be configured' do
    expect(values_found).not_to be_empty, "..."
  end
  it 'should satisfy <condition> wherever set' do
    expect(bad_values).to be_empty, "..."
  end
end
```

Common drop-file pairs to detect: `pwquality.conf` + `pwquality.conf.d/`, `sysctl.conf` + `sysctl.d/`, `rsyslog.conf` + `rsyslog.d/`, `profile` + `profile.d/*.sh`, `audit.rules` + `audit/rules.d/`, `sudoers` + `sudoers.d/`, `limits.conf` + `limits.d/`, `sssd.conf` + `sssd/conf.d/`.

### 3. Single-control body misplacement (wrong-sibling mapping)

**Symptom.** Code from a different control's body lands under this control's title/tags. Title says one thing; body checks something completely different.

**Canonical example: SV-274107.** Title: "Amazon Linux 2023 must off-load audit records onto a different system in the event the audit storage volume is full" (clearly about auditd's `disk_full_action`). Delta-generated body: checks `$DefaultNetstreamDriver` in rsyslog configs. mapControls picked the wrong sibling source; the rsyslog body landed under the auditd title/tags.

**Fix in branch:** commit `e832ba1` replaces the body with the correct `auditd_conf.disk_full_action` check + adds a `disk_full_action` input.

**Will's earlier commits already fixed many of these** — see `ef90f3e` (audit off-loading cluster SV-274069/077/079/080), `627c868` (SV-274018/274167 swap), `8663364` (5 misplaced bodies), `9719cde` (7 more misplaced bodies). The volume suggests this is not rare.

**Delta CLI improvement:** when the source-to-target mapping confidence is below a threshold (e.g. Jaccard < 70% AND not [primary] match), mark the output control with a clear `# DELTA-LOW-CONFIDENCE: source=SV-XXX, jaccard=N%` comment so reviewers can't skim past it.

### 4. Residual vendor strings (incomplete RHEL → AL rewrite)

**Symptom.** Strings inside `describe` block headlines, `only_if` reason messages, comment text, and skip messages still say "RHEL 9" after delta. Vendor-name rewriting only covered title/desc fields.

**Canonical example.** Will's commit `6578b3e` ("fixing more controls misplaced by delta, replacing RHEl --> AL strings throughout") and `5d7ffed` ("correctness fixes — paths, filters, gates, leftover RHEL strings"). String leftovers persisted across many controls.

**Delta CLI improvement:** add a final post-mapping pass that rewrites vendor mentions in **every** string-context site in the output Ruby:
- `describe '... headline ...'` block subjects
- `only_if('reason', ...)` reason strings
- `skip 'message'` strings
- Inline comments
- `expect(...).to ..., "failure_message"` second args

The current pass appears to only touch top-level `title` and `desc` fields.

### 5. Test shuffling (controls landed in wrong files)

**Symptom.** After delta, multiple controls had their test bodies placed in the wrong file altogether — needed to be moved between files. Same N→1 confusion as #1 but at file-placement scope.

**Evidence.** Will's commit `5c8c6f5`: "shuffle around some tests that landed on the wrong controlfile after delta run; full review needed."

**Delta CLI improvement:** after mapping, the output file's control ID should always match the control body inside it. A simple post-pass:

```
for each output_file in -o/controls/SV-XXX.rb:
    actual_control_id = parse SV-XXX from file
    declared_control_id = extract from `control 'SV-XXX' do` inside
    if actual_control_id != declared_control_id:
        ERROR: file/body mismatch, review SV-XXX
```

### 6. `find` flag bugs from delta-generated commands

**Symptom.** Commit `2af10df` notes "forgot a flag in the find commands in SV-27416[4,5] that made the profile open too many file descriptors." The delta-generated `find` invocations were missing `-xdev` and had issues passing array inputs.

**Delta CLI improvement:** when the source body contains a shell `find` invocation with input interpolation, ensure the rewrite handles `Array#to_s` correctly (use `.join(' ')`) and preserve `-xdev` where the source had it.

---

## CLI improvement themes — summary

If you're scoping work on `saf generate delta -M`, these are the high-value targets in priority order:

1. **N→1 mapping detection and handling.** Either warn the user, force per-target review, or annotate the output. This single class of bug accounts for the most hand-fixing across this pilot.
2. **STIG-text-aware post-mapping validation.** After mapping, parse the target's STIG check text and flag any carried-over assertions that don't appear in that text. The audit `-S all` cluster would have been caught instantly.
3. **Drop-file pattern detection.** When the target STIG check text says `X.conf X.conf.d/*.conf`, generate the iteration scaffold. Six controls in this pilot followed this pattern; covering it once in the CLI would eliminate it as a bug source forever.
4. **Vendor-string sweep across all string-context sites.** Today's pass covers titles and desc. Extend to describe block headlines, only_if reasons, skip messages, comments, failure_message strings.
5. **Confidence-gated output annotation.** Below a Jaccard threshold (50%? 60%?), mark the output control with `# DELTA-LOW-CONFIDENCE` so reviewers can't skim past it.

---

## The git commit chain (evidence)

For tracking which delta-induced bugs were fixed where:

```
cedd8bf  Import 187 AL2023 V1R3 controls derived from RHEL 9 V2r7 hybrid   ← initial delta output
1f2775b  updating tests that were not covered by the initial delta run     ← hand-fixing
5c8c6f5  shuffle around tests that landed on the wrong controlfile         ← test shuffling (#5)
6578b3e  fixing more controls misplaced by delta, replacing RHEl→AL        ← vendor strings (#4)
2af10df  forgot a flag in find commands in SV-27416[4,5]                  ← find flag bug (#6)
…
[Will's PR commits]
ef90f3e  rewire audit off-loading cluster (SV-274069/077/079/080)         ← single-control misplacement (#3)
627c868  unswap SV-274018 and SV-274167                                   ← single-control misplacement (#3)
8663364  restore correct code in 5 misplaced-code controls                ← single-control misplacement (#3)
9719cde  restore correct code in 7 more misplaced-code controls           ← single-control misplacement (#3)
5d7ffed  correctness fixes — paths, filters, gates, leftover RHEL strings ← mixed
e3d943d  correct find predicate for multi-group required_system_accounts  ← single-control misplacement (#3)
…
[May 2026 session commits]
e832ba1  correct delta misplacement on SV-274107                          ← single-control misplacement (#3)
c6a459d  remove stray '-S all' from 6 audit-command controls              ← N→1 template drift (#1)
81dbb7e  expand 6 pwquality controls to read .conf.d/ drop-files          ← drop-file miss (#2)
13f4975  SV-274069 skip message + SV-274142 guard-clause and drop-files  ← mixed
```

**Roughly 30+ controls required hand-fixing for delta-induced bugs across this pilot.** Each entry above is a concrete case the CLI could prevent with the improvements listed in the previous section.

---

## How this connects to the broader profile-derivation effort

This is the **AL2023 pilot** for a repeatable cross-vendor STIG profile-derivation workflow. The downstream queue includes RHEL 10, Debian 12, SLES, AMZN 2 refresh, Rocky 9. Each delta-CLI improvement here directly reduces hand-fixing cost across that queue.

The cookbook (`delta-provenance/cross-vendor-profile-derivation-cookbook.md`) is structured as "what we do / why / what goes wrong" and is intended to grow with each derivation. Extending its "what goes wrong" section with the patterns surfaced here would feed naturally into CLI improvement work.

---

## Suggested follow-up work

If a beads card is filed against `mitre/saf`, sensible scoping:

- **Phase A** (the cheap wins): N→1 detection + warning, vendor-string sweep, confidence annotation. Each is a relatively small code change to the existing delta pipeline.
- **Phase B** (medium): STIG-text-aware post-mapping validation. Requires the delta CLI to parse the target's STIG check text (already loaded for the mapping step) and apply assertion-vs-text consistency checks.
- **Phase C** (larger): Drop-file pattern detection and scaffold generation. Requires recognizing the `X.conf X.conf.d/*.conf` pattern in STIG check text and synthesizing the iteration template.

Phase A alone would have eliminated the majority of bugs in this pilot.
