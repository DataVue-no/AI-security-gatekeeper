---
name: New Attack Pattern
about: Propose a new L1 regex pattern or L2 structural check
title: '[PATTERN] '
labels: enhancement, patterns
assignees: ''
---

## Attack Class

Which threat category does this pattern target?
(See [threat-model.md](../../docs/threat-model.md) for the taxonomy)

- [ ] T1 Direct instruction override
- [ ] T2 Indirect injection from external data
- [ ] T3 Multi-agent infection
- [ ] T4 Crescendo / multi-turn escalation
- [ ] T5 Encoding evasion
- [ ] T6 XSS hybrid
- [ ] T7 False agent authority
- [ ] T8 System prompt leakage
- [ ] Novel — describe below

## Pattern

```python
# Proposed L1 pattern:
(r"your_regex_here", "attack-label"),
```

## Trigger Examples

Prompts that SHOULD trigger this pattern (these get blocked):
```
1. "..."
2. "..."
3. "..."
```

## False Positive Validation

Prompts that should NOT trigger this pattern (legitimate queries):
```
1. "..."
2. "..."
3. "..."
```

Please test against at least 5 legitimate queries relevant to your deployment domain.

## Source

Link to the attack technique, research paper, or real-world incident that motivated this pattern.

## Tier Recommendation

- [ ] Add to TRUSTED_L1 (authenticated users — indirect injection relevance)
- [ ] Add to PUBLIC_L1 only (unauthenticated users — direct attack relevance)
- [ ] Both tiers
