# Amazon Linux 2023 Security Technical Implementation Guide InSpec Profile

The Amazon Linux 2023 Security Technical Implementation Guide (AL2023 STIG) InSpec Profile can help programs automate their compliance checks of Amazon Linux 2023 systems to Department of Defense (DoD) requirements.

- Profile Version: `0.1.0`
- Amazon Linux 2023 Security Technical Implementation Guide V1R3 (benchmark date 01 Apr 2026)

The results of a profile run will provide information needed to support an Authority to Operate (ATO) decision for the applicable technology.

### Source Guidance

- Amazon Linux 2023 Security Technical Implementation Guide V1R3

## Status

**v0.1.0 — scaffolding.** Controls, kitchen configuration, and evaluation results will land in subsequent releases.

## Supported platform

- Amazon Linux 2023 (all 2023.x releases)

## Requirements

- InSpec ≥ 5.0 (7.x recommended)
- Ruby ≥ 3.1

## Planned release ladder

| Version | Contents |
|---------|----------|
| 0.1.0 | Repo scaffolding, empty `controls/`, design pinned |
| 0.2.0 | `saf generate delta` output committed, 187 controls populated (mix of RHEL9 carry-forward + AL2023 stubs) |
| 0.3.0 | Clean compile: `inspec check` + `rubocop` pass |
| 0.4.0 | Vanilla EC2 kitchen run succeeds; `vanilla.threshold.yml` pinned |
| 0.5.0 | `docs/al2023-vs-rhel9-diff.md` committed (hdf-libs structural diff) |
| 0.6.0 | GitHub Actions CI: check + lint on every PR, scheduled kitchen-ec2 |
| 1.0.0 | Hardening integration + hardened threshold |

## Authorship

Authored by: Aaron Lippold <lippold@gmail.com>
