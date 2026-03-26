---
name: Bypass Report (Security)
about: Report a way to bypass the current screening patterns
title: '[BYPASS] '
labels: security, bypass
assignees: ''
---

> ⚠️ **For confirmed bypasses with real attack potential, please use GitHub Security Advisories (private) rather than a public issue.**
> This public template is for borderline cases, near-misses, or theoretical bypasses.

## Bypass Category

- [ ] L1 pattern can be evaded with rephrasing
- [ ] L2 structural check can be bypassed
- [ ] Encoding evasion not caught
- [ ] Tier escalation (trusted → public attack surface expansion)
- [ ] False negative in specific language/domain context
- [ ] Other

## Description

A clear description of what the bypass achieves and how.

## Bypass Technique

```
The prompt or technique that bypasses current screening:
```

## Attack Class

What attack does this bypass enable? (instruction override / role switch / exfiltration / etc.)

## False Positive Impact

If we add a pattern to fix this, what legitimate queries might it affect?

```
Example legitimate queries that should NOT be blocked:
```

## Suggested Fix

If you have a regex or structural check that catches the bypass without excessive false positives, include it here.

## Source

If this bypass is based on published research, a CTF challenge, or a known attack technique, please link it.
