# Contributing to AI Security Gatekeeper

Thank you for considering a contribution. This project is specifically about sharing practical, production-tested security knowledge for agentic AI deployments. Quality and honesty are the priorities.

---

## What We're Looking For

### High-value contributions

**New L1 attack patterns**
- Include the attack string that triggers it
- Include 3+ legitimate queries that should NOT trigger it (false positive validation)
- Include a citation or real-world source for the attack technique
- Explain what makes this pattern novel vs. existing patterns

**Bypass reports (responsible disclosure)**
- If you find a way around the current patterns, please open a **private issue** first
- Include the bypass technique and what it enables
- We'll work with you to patch it before public disclosure
- You'll be credited in the changelog

**Deployment reports**
- What environment did you deploy this in? What did you have to tune?
- What false positives did you encounter and how did you resolve them?
- What attack attempts did you observe in production?
- What's missing from our threat model that matters in your context?

**Alternative architectures for root cause mitigations**
- Specifically: practical approaches to RC1 (L3 screening paradox), RC4 (technical enforcement), or RC5 (behavioural baseline)
- Must be implementable without quadratic overhead

**Community resources**
- Security blogs, researchers, newsletters actively tracking LLM injection attacks
- Red team reports from production deployments
- Tools for automated pattern regression testing
- CVE or advisory databases tracking prompt injection vulnerabilities

---

## What We're NOT Looking For

- More regex patterns for the same attack categories we already cover (marginal value)
- Theoretical frameworks without implementation guidance
- Patterns that generate unacceptable false positive rates on normal technical queries
- Security theatre additions that increase overhead without meaningfully improving posture
- "Could you also add X feature" requests not related to security screening

---

## How to Submit

### New attack patterns

1. Fork the repository
2. Add your pattern to `src/hook_screen.py` in the appropriate list (`TRUSTED_L1` or `PUBLIC_L1`)
3. Add a test case to `tests/test_patterns.py`:
```python
def test_your_pattern_name():
    # Should trigger
    assert screen("your attack string here", "public")["verdict"] == "BLOCK"
    # Should NOT trigger (false positive checks)
    assert screen("legitimate query 1", "public")["verdict"] == "CLEAR"
    assert screen("legitimate query 2", "public")["verdict"] == "CLEAR"
```
4. Add an entry to the threat model table in `docs/threat-model.md`
5. Open a pull request with:
   - The source/reference for this attack technique
   - False positive validation results
   - Any edge cases you found

### Bypass reports

Open a **private security advisory** via GitHub Security Advisories, not a public issue. Include:
- The bypass technique
- What attack class it enables
- Suggested fix (if you have one)

### Discussion contributions

Use [GitHub Discussions](../../discussions) for:
- Questions about the architecture
- Your deployment experience
- Proposals that need community input before implementation
- Resources to add to the community reading list

---

## Code Style

- Python 3.10+ with type hints
- No external dependencies (stdlib only)
- Every pattern must have a comment explaining the attack class it targets
- Prefer clarity over cleverness — this code is read by people trying to understand a security system

---

## The Things We Argue About (Join In)

Open questions where we genuinely don't have the right answer and would value input:

1. **L3 screening paradox** (RC1): Is there a practical solution that doesn't require a second isolated model call?
2. **Crescendo detection** (T4): Session-aware screening without session storage — is this achievable?
3. **Threshold calibration** (RC5): What's the right methodology before you have labelled attack data?
4. **Public-tier rate limiting**: Is 20 requests/minute the right default? How should it vary by deployment context?
5. **Multi-agent trust**: What's the right primitive for inter-agent message authentication in Claude Code?

GitHub Discussions is the right place for these conversations.
