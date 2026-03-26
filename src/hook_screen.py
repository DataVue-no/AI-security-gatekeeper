#!/usr/bin/env python3
"""
AI Security Gatekeeper — UserPromptSubmit Hook
===============================================
A defence-in-depth security screening hook for Claude Code deployments.
Implements three-tier screening optimised for cost-vs-security trade-offs.

ARCHITECTURE:
  UserPromptSubmit hook → L1 (regex) + L2 (structural) → verdict → context injection → Claude

SECURITY TIERS:
  system   SECURITY_TIER=system  (CI/CD, cron, automated pipelines)
           → No screening. Machine-generated prompts are implicitly trusted.
             Add your own validation at the pipeline level.

  trusted  Default for authenticated users (configure TRUSTED_USERS)
           → Lightweight screening: indirect injection only.
             Rationale: an authenticated user already has shell access;
             "ignore previous instructions" adds no new attack surface.
             Real risk: external data (DB records, web fetches) containing injections.

  public   SECURITY_TIER=public  (unauthenticated users)
           → Full screening: 18 L1 patterns + encoding evasion + L2 structural analysis.

EXIT CODES (Claude Code UserPromptSubmit hook protocol):
  0  → pass  — stdout is injected as context before Claude sees the prompt
  2  → block — stdout is shown to the user, prompt is not processed

OWASP LLM TOP 10 (2025) COVERAGE:
  LLM01 Prompt Injection      ✓  L1 patterns + encoding evasion detection
  LLM06 Excessive Agency      ✓  Destructive operation blocking
  LLM07 System Prompt Leakage ✓  Exfiltration pattern detection

REFERENCES:
  - OWASP LLM Top 10 (2025): https://owasp.org/www-project-top-10-for-large-language-model-applications/
  - Agents Rule of Two (Oso/Meta 2025): agents processing untrusted input must not
    simultaneously hold sensitive data access AND state-change capabilities
  - Claude Code hooks: https://docs.anthropic.com/claude-code/hooks
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
import os
import re
import sys
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration — adjust for your deployment
# ---------------------------------------------------------------------------

# Path for JSONL audit log (one record per prompt)
AUDIT_LOG = Path(os.environ.get("GATEKEEPER_AUDIT_LOG", "./logs/security_audit.jsonl"))

# Users treated as trusted (authenticated, can run shell commands directly)
# These get lightweight screening rather than full public-tier screening
TRUSTED_USERS: set[str] = {
    # Add your authenticated usernames here
    # "alice", "bob",
}

# Rate limiting for public tier (unauthenticated users)
RATE_LIMIT_FILE = Path("/tmp/gatekeeper_rate.json")
RATE_LIMIT_WINDOW_S = 60
RATE_LIMIT_MAX_PUBLIC = 20

# LLM families with explicit security profiles (see docs/llm-security-profiles.md)
SUPPORTED_FAMILIES = {"claude", "openai", "copilot", "gemini"}

# ---------------------------------------------------------------------------
# Tier detection
# ---------------------------------------------------------------------------

def get_security_tier() -> str:
    """
    Determine the security tier for this invocation.

    Explicit env var always wins. Falls back to user identity detection.
    Default: 'trusted' (assumes authenticated shell session).
    Override to 'public' when exposing Claude Code to unauthenticated users.
    """
    explicit = os.environ.get("SECURITY_TIER", "").lower()
    if explicit == "system":
        return "system"
    if explicit == "public":
        return "public"
    current_user = os.environ.get("USER", os.environ.get("LOGNAME", ""))
    if current_user in TRUSTED_USERS or explicit == "trusted":
        return "trusted"
    return "trusted"  # safe default: treat as authenticated session

# ---------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------

def audit_log(record: dict) -> None:
    """Append a structured record to the JSONL audit log. Never raises."""
    try:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        with AUDIT_LOG.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:
        pass  # never let logging break the hook

# ---------------------------------------------------------------------------
# LLM family detection
# ---------------------------------------------------------------------------

def detect_llm() -> dict:
    """
    Detect active LLM family from environment variables.

    Different LLM families have meaningfully different injection risk profiles.
    See docs/llm-security-profiles.md for per-family analysis.
    """
    if os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("CLAUDE_CODE_VERSION"):
        return {"id": os.environ.get("ANTHROPIC_MODEL", "claude-sonnet"), "family": "claude"}
    if os.environ.get("GITHUB_COPILOT_TOKEN") or os.environ.get("COPILOT_AGENT"):
        return {"id": "copilot", "family": "copilot"}
    if os.environ.get("OPENAI_API_KEY"):
        return {"id": os.environ.get("OPENAI_MODEL", "gpt-4o"), "family": "openai"}
    if os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY"):
        return {"id": os.environ.get("GEMINI_MODEL", "gemini-2.0-flash"), "family": "gemini"}
    return {"id": "claude-sonnet", "family": "claude"}

# ---------------------------------------------------------------------------
# L1 — Regex patterns: trusted tier (authenticated users)
#
# Rationale: an authenticated user already has shell/system access.
# Direct jailbreak attempts ("ignore previous instructions") are irrelevant —
# they can just run the command themselves.
#
# The only real threat is indirect injection: malicious content embedded in
# external data sources (database records, web fetches, file contents) that
# the LLM processes and acts on.
# ---------------------------------------------------------------------------

TRUSTED_L1: list[tuple[str, str]] = [
    # Destructive SQL via data source (e.g. a malicious value in a database field)
    (r"(?i)\b(drop\s+table|truncate\s+table|delete\s+from\s+\w+\s*(?:where\s+1|;|$))\b",
     "destructive-sql"),

    # Multi-agent infection: external data instructing the agent to propagate malicious payload
    (r"(?i)(pass\s+this\s+(to|on\s+to)|forward\s+to\s+(next|other|all)\s+agent|inject\s+into\s+(brief|output|context))",
     "multi-agent-infection"),

    # Output payload injection: condition the LLM to embed malicious content in its response
    (r"(?i)(when\s+you\s+(output|respond|generate).{0,50}(include|append|add)\s+.{0,50}(ignore|override|you are))",
     "output-payload-injection"),

    # Null byte — may appear in binary file contents processed by the LLM
    (r"\x00", "null-byte-injection"),

    # Config/secret exfiltration via external data source
    (r"(?i)(dump|export|extract|reveal)\s+.{0,40}(system.?prompt|\.env|DATABASE_URL|SMTP|api.?key)",
     "config-exfiltration"),
]

# L2 structural checks for trusted tier (lightweight)
def trusted_l2(prompt: str) -> list[str]:
    """
    Structural anomaly detection for authenticated sessions.
    Focuses on signs that processed external data may be injected.
    """
    flags: list[str] = []
    if len(prompt) > 12_000:
        # Very long prompts often indicate large external data being processed
        flags.append(f"excessive-length:{len(prompt)}-chars")
    if re.search(r"[\u200b\u200c\u200d\u00ad\u2060\ufeff\u180e]", prompt):
        # Invisible Unicode characters — common in copy-paste attacks from external sources
        flags.append("invisible-unicode-chars")
    return flags

# ---------------------------------------------------------------------------
# L1 — Regex patterns: public tier (unauthenticated users)
#
# Full coverage of OWASP LLM01 attack categories.
# Must balance false-positive rate against detection coverage.
# Tune thresholds based on your audit log baseline (see docs/cost-benefit-analysis.md).
# ---------------------------------------------------------------------------

PUBLIC_L1: list[tuple[str, str]] = [
    # Direct instruction override — classic prompt injection
    (r"(?i)(ignore|forget|disregard|override)\s+(all\s+)?(previous|prior|above|your)\s+(instructions?|rules?|constraints?)",
     "instruction-override"),

    # Role/persona hijacking
    (r"(?i)(you are now|pretend you are|act as if you are|your new (role|persona|identity) is)",
     "role-switch"),

    # System tag injection — attempts to inject content that looks like a system message
    (r"(?i)(<\s*system\s*>|</?\s*instructions?\s*>|##\s*system\s*##)\s*[:\-]?\s*\w",
     "system-tag-injection"),

    # Privilege escalation
    (r"(?i)(admin|root|superuser|privileged)\s*(mode|access|override|bypass)",
     "privilege-escalation"),

    # Debug/maintenance mode bypass
    (r"(?i)(maintenance|debug|bypass)\s*(mode|access|override)",
     "debug-mode-bypass"),

    # Jailbreak keywords
    (r"(?i)\b(jailbreak|do\s+anything\s+now|DAN\b|developer\s+mode|unrestricted\s+mode|god\s+mode)",
     "jailbreak-attempt"),

    # Secret/credential exfiltration
    (r"(?i)(send|email|forward|transmit|upload|exfil)\s+.{0,60}(password|secret|api.?key|token|credentials?)",
     "secret-exfiltration"),

    # Config/environment exfiltration
    (r"(?i)(dump|export|extract|reveal|expose|print|show|cat)\s+.{0,40}(system.?prompt|\.env|\.secrets?|DATABASE_URL|SMTP)",
     "config-exfiltration"),

    # Direct file read for secrets
    (r"(?i)(read|cat|open|view)\s+.{0,30}(\.env|\.secrets?\.env|credentials?|api.?key)",
     "secret-file-read"),

    # False agent/system authority claims
    (r"(?i)\[?\s*(from|message\s+from|instruction\s+from|sent\s+by)\s*[:\-]?\s*(system|admin|gatekeeper|orchestrator|claude)\s*\]?",
     "false-agent-authority"),

    # Fake authorisation codes
    (r"(?i)(priority\s*code|override\s*code|emergency\s*access|master\s*key)\s*[:=]",
     "false-auth-code"),

    # Destructive SQL
    (r"(?i)\b(drop\s+table|truncate\s+table|delete\s+from\s+\w+\s*(?:where\s+1|;|$))\b",
     "destructive-sql"),

    # Data list exfiltration (adapt to your domain data)
    (r"(?i)(list|dump|export)\s+.{0,30}(all\s+)?(users?|subscribers?|emails?|customer)",
     "data-list-exfiltration"),

    # XSS hybrid injection (relevant when LLM output is rendered in a browser)
    (r"(?i)<\s*script[^>]*>.*?(?:ignore|override|you are|system|eval|fetch|xhr)",
     "xss-hybrid-injection"),

    # XSS event handler injection
    (r"(?i)(on(load|click|error|mouseover|submit)\s*=\s*[\"']?[^\"']*(?:ignore|override|fetch|eval))",
     "xss-event-injection"),

    # JavaScript URL injection
    (r"(?i)javascript\s*:[^;]{0,100}(?:ignore|override|system|fetch|eval|atob)",
     "javascript-url-injection"),

    # Multi-agent infection (self-propagating payloads across agent chains)
    (r"(?i)(pass\s+this\s+(to|on\s+to)|forward\s+to\s+(next|other|all)\s+agent|inject\s+into\s+(brief|output|context))",
     "multi-agent-infection"),

    # Output payload injection
    (r"(?i)(when\s+you\s+(output|respond|generate).{0,50}(include|append|add)\s+.{0,50}(ignore|override|you are))",
     "output-payload-injection"),
]

# ---------------------------------------------------------------------------
# Encoding evasion detection (public tier only)
#
# Attackers frequently encode injection payloads to bypass regex patterns.
# We decode and re-scan. Heuristics used to avoid false positives.
# ---------------------------------------------------------------------------

NULL_BYTE          = re.compile(r"\x00|\0")
HEX_ESCAPE_DENSE   = re.compile(r"(?:\\x[0-9a-fA-F]{2}){6,}")
URL_PERCENT_DENSE  = re.compile(r"(?:%[0-9a-fA-F]{2}){8,}")
UNICODE_ESC_DENSE  = re.compile(r"(?:\\u[0-9a-fA-F]{4}){6,}")
HTML_ENTITY_DENSE  = re.compile(r"(?:&#\d{2,4};){8,}")
HOMOGLYPH_RE       = re.compile(r"[а-яёА-ЯЁ\u0370-\u03FF\u1F00-\u1FFF]")
INVISIBLE_RE       = re.compile(r"[\u200b\u200c\u200d\u00ad\u2060\ufeff\u180e]")
UNEXPECTED_TAGS    = re.compile(r"(?i)<\s*(system|instructions?|prompt|role|context)\s*>")
REPETITIVE_RE      = re.compile(
    r"(?i)(ignore|override|you are).{0,80}(ignore|override|you are).{0,80}(ignore|override|you are)",
    re.DOTALL)


def non_printable_ratio(text: str) -> float:
    """
    Fraction of non-printable characters. >8% suggests binary/obfuscated content.
    Extend the exclusion set with language-specific characters for your locale.
    """
    if not text:
        return 0.0
    return sum(1 for c in text if not c.isprintable() and c not in "\n\r\t") / len(text)


def check_base64(text: str, patterns: list) -> bool:
    """Decode base64 blobs and re-scan against L1 patterns."""
    b64 = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
    for m in b64.finditer(text):
        try:
            decoded = base64.b64decode(m.group() + "==").decode("utf-8", errors="ignore")
            if any(re.search(p, decoded) for p, _ in patterns):
                return True
        except Exception:
            pass
    return False


def encoding_evasion_flags(prompt: str, patterns: list) -> list[str]:
    """
    Detect encoding-based evasion. Decodes each encoding scheme and re-scans.
    Returns flag labels for any hits.
    """
    flags: list[str] = []

    if NULL_BYTE.search(prompt):
        flags.append("null-byte-injection")

    def rescan(decoded: str, prefix: str) -> None:
        for p, lbl in patterns:
            if re.search(p, decoded):
                flags.append(f"{prefix}-encoded-{lbl}")

    if HEX_ESCAPE_DENSE.search(prompt):
        flags.append("hex-encoding-evasion")
        try:
            rescan(prompt.encode().decode("unicode_escape", errors="ignore"), "hex")
        except Exception:
            pass

    if URL_PERCENT_DENSE.search(prompt):
        flags.append("url-encoding-evasion")
        try:
            rescan(urllib.parse.unquote(prompt), "url")
        except Exception:
            pass

    if UNICODE_ESC_DENSE.search(prompt):
        flags.append("unicode-escape-evasion")
        try:
            rescan(prompt.encode().decode("unicode_escape", errors="ignore"), "unicode")
        except Exception:
            pass

    if HTML_ENTITY_DENSE.search(prompt):
        flags.append("html-entity-evasion")
        try:
            rescan(html.unescape(prompt), "html")
        except Exception:
            pass

    if non_printable_ratio(prompt) > 0.08:
        flags.append("binary-blob-content")

    return flags


def public_l2(prompt: str) -> list[str]:
    """Full structural analysis for public-tier prompts."""
    flags: list[str] = []

    if len(prompt) > 8_000:
        flags.append(f"excessive-length:{len(prompt)}-chars")

    if HOMOGLYPH_RE.search(prompt):
        # Cyrillic/Greek lookalikes substituted for ASCII in injection keywords
        flags.append("homoglyph-substitution")

    if INVISIBLE_RE.search(prompt):
        flags.append("invisible-unicode-chars")

    if UNEXPECTED_TAGS.search(prompt):
        # XML/HTML structures attempting to mimic system message framing
        flags.append("system-tag-nesting")

    if REPETITIVE_RE.search(prompt):
        # Repeated override keywords — context overflow / token flooding attempt
        flags.append("repetitive-override-pattern")

    words = prompt.split()
    if len(words) > 50 and len(set(words)) / len(words) < 0.35:
        # Very low lexical diversity in a long prompt → context flooding
        flags.append("context-flood-repetition")

    return flags

# ---------------------------------------------------------------------------
# Rate limiting (public tier only)
# ---------------------------------------------------------------------------

def check_rate_limit_public() -> bool:
    """
    Simple in-process rate limiter for public-tier prompts.
    Returns True if the limit is exceeded (caller should block).
    For production: replace with Redis or a proper rate limiting service.
    """
    now = time.time()
    try:
        data = json.loads(RATE_LIMIT_FILE.read_text()) if RATE_LIMIT_FILE.exists() else {"calls": []}
    except Exception:
        data = {"calls": []}
    calls = [t for t in data.get("calls", []) if now - t < RATE_LIMIT_WINDOW_S]
    exceeded = len(calls) >= RATE_LIMIT_MAX_PUBLIC
    try:
        RATE_LIMIT_FILE.write_text(json.dumps({"calls": (calls + [now])[-200:]}))
    except Exception:
        pass
    return exceeded

# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def sha256_short(text: str) -> str:
    """Short hash for audit log correlation (not for security — just correlation)."""
    return hashlib.sha256(text.encode()).hexdigest()[:16]

# ---------------------------------------------------------------------------
# Core screening logic
# ---------------------------------------------------------------------------

def screen(prompt: str, tier: str) -> dict:
    """
    Run L1 + L2 screening for the given tier.

    Returns a result dict with verdict, flags, and metadata.
    Verdict:
      CLEAR      — no flags (proceed normally)
      SUSPICIOUS — one L2 flag (proceed with reduced capabilities)
      BLOCK      — one or more L1 flags OR two+ L2 flags (reject)
    """
    l1_flags: list[str] = []
    l2_flags: list[str] = []

    if tier == "trusted":
        # Authenticated users: lightweight indirect-injection check only
        for pattern, label in TRUSTED_L1:
            if re.search(pattern, prompt):
                l1_flags.append(label)
        l2_flags = trusted_l2(prompt)

    else:  # public — full screening
        for pattern, label in PUBLIC_L1:
            if re.search(pattern, prompt):
                l1_flags.append(label)
        if check_base64(prompt, PUBLIC_L1):
            l1_flags.append("base64-encoded-injection")
        l1_flags.extend(encoding_evasion_flags(prompt, PUBLIC_L1))
        l2_flags = public_l2(prompt)

    if l1_flags or len(l2_flags) >= 2:
        verdict = "BLOCK"
    elif len(l2_flags) == 1:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAR"

    return {
        "verdict": verdict,
        "tier": tier,
        "l1_flags": l1_flags,
        "l2_flags": l2_flags,
        "prompt_hash": sha256_short(prompt),
        "prompt_length": len(prompt),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

# ---------------------------------------------------------------------------
# Output builders
# ---------------------------------------------------------------------------

def build_context_xml(result: dict, llm: dict) -> str:
    """
    Build the context string injected before the prompt reaches Claude.
    For SUSPICIOUS prompts, include a warning visible to the LLM.
    This string is injected as context via exit code 0 + stdout.
    """
    verdict = result["verdict"]
    tier = result["tier"]
    llm_ok = "yes" if llm["family"] in SUPPORTED_FAMILIES else "no"

    warning = ""
    if verdict == "SUSPICIOUS":
        warning = (
            f'\n  <warning>⚠️ SUSPICIOUS prompt ({tier}-tier) — '
            f'{", ".join(result["l2_flags"])}. '
            f'Restrict to read-only operations.</warning>'
        )

    return (
        f'<security_screening>\n'
        f'  <verdict>{verdict}</verdict>\n'
        f'  <tier>{tier}</tier>\n'
        f'  <l1_flags>{", ".join(result["l1_flags"]) or "none"}</l1_flags>\n'
        f'  <l2_flags>{", ".join(result["l2_flags"]) or "none"}</l2_flags>\n'
        f'  <prompt_hash>{result["prompt_hash"]}</prompt_hash>\n'
        f'  <timestamp>{result["timestamp"]}</timestamp>{warning}\n'
        f'  <llm family="{llm["family"]}" model="{llm["id"]}" supported="{llm_ok}"/>\n'
        f'</security_screening>'
    )


def build_block_message(result: dict) -> str:
    flags = result["l1_flags"] + result["l2_flags"]
    return (
        f"⛔ Request blocked by security screening ({result['tier']} tier).\n"
        f"Reason: {', '.join(flags)}\n"
        f"Reference: {result['prompt_hash']}\n"
        f"If you believe this is a false positive, please open an issue."
    )

# ---------------------------------------------------------------------------
# System-tier passthrough
# ---------------------------------------------------------------------------

def system_passthrough(ts: str) -> None:
    """
    Automated pipeline bypass. No screening performed.
    Set SECURITY_TIER=system in crontabs and CI/CD scripts.
    """
    audit_log({"verdict": "SYSTEM_TRUSTED", "tier": "system", "timestamp": ts})
    print('<security_screening verdict="SYSTEM_TRUSTED" tier="system">Automated pipeline.</security_screening>')
    sys.exit(0)

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    ts = datetime.now(timezone.utc).isoformat()
    tier = get_security_tier()

    if tier == "system":
        system_passthrough(ts)
        return

    # Read prompt from stdin (Claude Code passes it as JSON)
    raw = sys.stdin.read().strip()
    prompt = ""
    if raw:
        try:
            data = json.loads(raw)
            prompt = data.get("prompt", "") or data.get("message", "") or raw
        except (json.JSONDecodeError, AttributeError):
            prompt = raw

    if not prompt:
        audit_log({"verdict": "CLEAR", "tier": tier, "reason": "empty_prompt", "timestamp": ts})
        print(f'<security_screening verdict="CLEAR" tier="{tier}">Empty prompt.</security_screening>')
        sys.exit(0)

    # Rate limiting for public tier
    if tier == "public" and check_rate_limit_public():
        audit_log({"verdict": "BLOCK", "tier": "public", "reason": "rate-limit",
                   "prompt_hash": sha256_short(prompt), "timestamp": ts})
        print("⛔ Rate limit exceeded. Please wait before sending another request.")
        sys.exit(2)

    llm = detect_llm()
    result = screen(prompt, tier)

    # Structured audit record
    audit_log({
        "verdict": result["verdict"],
        "tier": tier,
        "l1_flags": result["l1_flags"],
        "l2_flags": result["l2_flags"],
        "prompt_hash": result["prompt_hash"],
        "prompt_length": result["prompt_length"],
        "llm_family": llm["family"],
        "timestamp": result["timestamp"],
    })

    if result["verdict"] == "BLOCK":
        print(build_block_message(result))
        sys.exit(2)
    else:
        print(build_context_xml(result, llm))
        sys.exit(0)


if __name__ == "__main__":
    main()
