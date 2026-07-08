# willow/fylgja/safety/security_scan.py
# Prompt-injection and command-safety scanner for PreToolUse / PostToolUse hooks.
#
# Stolen cleanly from aviv4339/claude-guard (MIT) — adapted to Willow's hook
# architecture, severity model, and PIIMatch dataclass style.
#
# What changed vs upstream:
#   - Severity enum replaced with plain int constants (0-3) matching Willow's existing
#     pii_detect.PIIMatch.severity field so both systems speak the same language.
#   - Result type is ScanIssue (modelled on PIIMatch) instead of a bare dataclass.
#   - No YAML config loading — Willow uses env vars and settings.json; we expose a
#     simple `scan_bash()`, `scan_write()`, and `scan_output()` API.
#   - Allowlist is passed as an argument rather than read from disk.
#   - Leetspeak and hidden-text categories added from claude-guard's full pattern set.
#
# b17: SECSCAN  ΔΣ=42

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Sequence

# ── Severity constants (matches pii_detect.PIIMatch.severity scale) ───────────
SEV_LOW = 0       # log only — never blocks
SEV_MEDIUM = 1    # advisory
SEV_HIGH = 2      # block at default sensitivity
SEV_CRITICAL = 3  # always blocks


@dataclass
class ScanIssue:
    """Single security concern found during tool validation."""
    category: str     # e.g. "exfiltration", "prompt_injection"
    severity: int     # 0–3
    pattern: str      # the regex string that matched
    message: str      # human-readable explanation


# ── Pattern helpers ────────────────────────────────────────────────────────────

PatternEntry = tuple[re.Pattern, int, str]  # (compiled, severity, message)


def _compile(entries: list[tuple[str, int, str]]) -> list[PatternEntry]:
    return [(re.compile(p, re.IGNORECASE | re.MULTILINE), sev, msg)
            for p, sev, msg in entries]


def _check(text: str, patterns: list[PatternEntry], category: str) -> list[ScanIssue]:
    issues: list[ScanIssue] = []
    for regex, severity, message in patterns:
        if regex.search(text):
            issues.append(ScanIssue(
                category=category,
                severity=severity,
                pattern=regex.pattern,
                message=message,
            ))
    return issues


# ── PreToolUse: Bash command patterns ─────────────────────────────────────────

_EXFIL = _compile([
    (r"cat\s+.*\.(env|pem|key|secret|credentials).*\|.*(curl|wget|nc|ncat)",
     SEV_CRITICAL, "Piping secret file to network command"),
    (r"curl\s+.*-d\s+@", SEV_CRITICAL, "curl POST with local file (@file)"),
    (r"curl\s+.*--data.*\$\(", SEV_CRITICAL, "curl POST with command substitution"),
    (r"curl\s+.*--upload-file", SEV_CRITICAL, "curl uploading local file"),
    (r"wget\s+.*--post-file", SEV_CRITICAL, "wget POST with local file"),
    (r"base64.*\|.*(curl|wget|nc)", SEV_CRITICAL, "Base64-encoded data sent to network"),
    (r"xxd.*\|.*(curl|wget|nc)", SEV_CRITICAL, "Hex-encoded data sent to network"),
    (r"\$\(.*\)\..*\.(com|net|org|io)", SEV_CRITICAL, "DNS exfiltration via command substitution"),
    (r"dig\s+.*\$\(", SEV_CRITICAL, "DNS exfiltration via dig"),
    (r"nslookup\s+.*\$\(", SEV_CRITICAL, "DNS exfiltration via nslookup"),
    (r"bash\s+-i\s+>&\s*/dev/tcp", SEV_CRITICAL, "Reverse shell via /dev/tcp"),
    (r"nc\s+.*-e\s+/bin/(ba)?sh", SEV_CRITICAL, "Reverse shell via netcat"),
    (r"python.*socket.*connect", SEV_HIGH, "Possible reverse shell via Python socket"),
    (r"mkfifo\s+/tmp/.*\|\s*/bin/sh", SEV_CRITICAL, "Reverse shell via named pipe"),
    (r"nohup\s+.*(curl|wget|nc)", SEV_HIGH, "Background network exfiltration command"),
])

_SECRET_ACCESS = _compile([
    (r"cat\s+.*\.ssh/(id_rsa|id_ed25519|id_ecdsa)", SEV_CRITICAL, "Reading SSH private key"),
    (r"cat\s+.*\.aws/credentials", SEV_CRITICAL, "Reading AWS credentials"),
    (r"cat\s+.*\.kube/config", SEV_HIGH, "Reading Kubernetes config"),
    (r"cat\s+.*\.docker/config\.json", SEV_HIGH, "Reading Docker config (may contain auth)"),
    (r"cat\s+.*\.env(\s|$|\.\w)", SEV_HIGH, "Reading .env file"),
    (r"(echo|printf)\s+.*\$(.*PASSWORD|.*SECRET|.*TOKEN|.*API_KEY)",
     SEV_HIGH, "Printing secret environment variable"),
    (r"printenv.*(PASSWORD|SECRET|TOKEN|API_KEY)", SEV_HIGH, "Printing secret env var"),
    (r"cat\s+.*(\.bash_history|\.zsh_history)", SEV_HIGH, "Reading shell history"),
    (r"(^|\|)\s*(env|set)\s*\|.*grep.*(PASSWORD|SECRET|TOKEN|API_KEY|CREDENTIALS)",
     SEV_HIGH, "Grepping environment for secrets"),
])

_DESTRUCTIVE = _compile([
    (r"rm\s+-rf\s+/\s", SEV_CRITICAL, "rm -rf / (root filesystem)"),
    (r"rm\s+-rf\s+/\*", SEV_CRITICAL, "rm -rf /* (root filesystem wildcard)"),
    (r"git\s+push\s+.*--force\s+.*(main|master)", SEV_HIGH, "Force push to main/master"),
    (r"git\s+reset\s+--hard", SEV_HIGH, "git reset --hard (discards changes)"),
    (r"git\s+clean\s+-fd", SEV_HIGH, "git clean -fd (deletes untracked files)"),
    (r"(DROP|TRUNCATE)\s+(TABLE|DATABASE|SCHEMA)", SEV_HIGH, "SQL destructive statement"),
    (r"(mkfs|dd\s+if=.*of=/dev|fdisk)", SEV_CRITICAL, "Low-level disk operation"),
    (r"chmod\s+(-R\s+)?777\s+/", SEV_HIGH, "Setting world-writable permissions on system path"),
    (r"chown\s+-R\s+.*\s+/", SEV_HIGH, "Recursive ownership change on system path"),
])

_RM_RF_RE = re.compile(
    r"rm\s+(-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*|-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*)\s+([^;&|`\n]+)",
    re.IGNORECASE,
)
_SYSTEM_ROOT_RE = re.compile(r"^/(?:usr|etc|var|opt|bin|sbin|lib)(?:/|$)")


def _rm_rf_targets(command: str) -> list[str]:
    """Whitespace-split rm -rf targets (no full shell parse)."""
    targets: list[str] = []
    for match in _RM_RF_RE.finditer(command):
        tail = match.group(2).strip().split("#", 1)[0].strip()
        for token in tail.split():
            if token and not token.startswith("-"):
                targets.append(token)
    return targets


def _is_destructive_rm_target(target: str) -> bool:
    """Depth-aware rm -rf check — /home/* is not blanket-dangerous when under /worktrees/."""
    path = target.strip().rstrip("/")
    if not path or path == "*":
        return True
    if path in ("/", "/*"):
        return True
    if path == "~" or path.startswith("~/"):
        return True
    normalized = path.replace("\\", "/")
    if "/worktrees/" in normalized:
        return False
    if _SYSTEM_ROOT_RE.match(path):
        return True
    if path == "/home" or path.startswith("/home/"):
        return True
    return False


def _check_destructive_rm(command: str) -> list[ScanIssue]:
    issues: list[ScanIssue] = []
    for target in _rm_rf_targets(command):
        if not _is_destructive_rm_target(target):
            continue
        critical = target.strip() in ("/", "/*")
        issues.append(
            ScanIssue(
                category="destructive",
                severity=SEV_CRITICAL if critical else SEV_HIGH,
                pattern="rm-rf",
                message=(
                    "rm -rf / (root filesystem)"
                    if critical
                    else f"Forced recursive deletion of important path: {target}"
                ),
            )
        )
    return issues


_SUSPICIOUS_INSTALL = _compile([
    (r"curl\s+.*\|\s*(sudo\s+)?(ba)?sh", SEV_HIGH, "Piping curl output to shell"),
    (r"wget\s+.*\|\s*(sudo\s+)?(ba)?sh", SEV_HIGH, "Piping wget output to shell"),
    (r"pip\s+install\s+https?://(?!pypi\.org)", SEV_MEDIUM, "pip install from non-PyPI URL"),
    (r"npm\s+install\s+https?://(?!registry\.npmjs)", SEV_MEDIUM, "npm install from non-registry URL"),
    (r"python3?\s+-c\s+.*urllib.*urlopen", SEV_MEDIUM, "Python one-liner fetching remote code"),
])

_OBFUSCATION = _compile([
    (r"echo\s+[A-Za-z0-9+/=]{8,}\s*\|\s*base64\s+-d\s*\|\s*(ba)?sh",
     SEV_CRITICAL, "Executing base64-encoded shell command"),
    (r"echo\s+.*\\x[0-9a-f]{2}.*\|\s*(ba)?sh", SEV_CRITICAL, "Executing hex-encoded shell command"),
    (r"\$\{[a-z]:0:1\}", SEV_HIGH, "Character-by-character variable obfuscation"),
    (r"eval\s+\$\(.*base64", SEV_CRITICAL, "eval with base64-decoded content"),
    (r"eval\s+.*\\x[0-9a-f]", SEV_CRITICAL, "eval with hex-encoded content"),
])

# ── PreToolUse: Write/Edit path and content patterns ──────────────────────────

_PROTECTED_PATHS = _compile([
    (r"\.ssh/", SEV_CRITICAL, "SSH directory"),
    (r"\.gnupg/", SEV_CRITICAL, "GPG directory"),
    (r"\.aws/credentials", SEV_CRITICAL, "AWS credentials"),
    (r"\.env$", SEV_HIGH, ".env file"),
    (r"\.env\.", SEV_HIGH, ".env variant file"),
    (r"\.kube/config", SEV_HIGH, "Kubernetes config"),
    (r"\.docker/config\.json", SEV_HIGH, "Docker config"),
    (r"\.npmrc$", SEV_HIGH, "npm auth config"),
    (r"\.pypirc$", SEV_HIGH, "PyPI auth config"),
    (r"\.netrc$", SEV_CRITICAL, "netrc credentials"),
    (r"/etc/(passwd|shadow|sudoers)", SEV_CRITICAL, "System auth file"),
    (r"authorized_keys$", SEV_CRITICAL, "SSH authorized_keys"),
    (r"id_rsa|id_ed25519", SEV_CRITICAL, "SSH private key"),
])

_CONTENT_INJECTION = _compile([
    (r"(?:subprocess|os\.system|exec)\s*(?:\.\w+)?\s*\(\s*['\"].*(?:curl|wget|nc)\s+",
     SEV_HIGH, "Shell command execution with network tool in code"),
    (r"base64\.b64decode\(['\"][A-Za-z0-9+/=]{50,}",
     SEV_HIGH, "Large base64-encoded payload in code"),
    (r"\*\s+\*\s+\*\s+\*\s+\*.*(curl|wget|nc|python|bash)",
     SEV_HIGH, "Cron job with network/shell command"),
])

# ── PostToolUse: prompt injection signatures ───────────────────────────────────

_INJECTION = _compile([
    (r"ignore\s+(all\s+)?previous\s+instructions", SEV_HIGH, "Instruction override attempt"),
    (r"ignore\s+(all\s+)?prior\s+(instructions|prompts|context)", SEV_HIGH, "Instruction override attempt"),
    (r"disregard\s+(all\s+)?(previous|prior|above)", SEV_HIGH, "Instruction override attempt"),
    (r"forget\s+(all\s+)?(previous|prior|above|your)\s+(instructions|context|training|rules)",
     SEV_HIGH, "Instruction override attempt"),
    (r"override\s+(all\s+)?(system|safety|previous)\s+(prompt|instructions)",
     SEV_HIGH, "System prompt override attempt"),
    (r"new\s+system\s+prompt\s*:", SEV_HIGH, "System prompt injection"),
    (r"your\s+new\s+instructions\s+(are|:)", SEV_HIGH, "Instruction replacement attempt"),
    (r"from\s+now\s+on,?\s+you\s+(will|must|should|are)\s+", SEV_HIGH, "Instruction redefinition"),
    (r"(reset|clear|wipe)\s+(your\s+)?(context|memory|instructions|slate)", SEV_HIGH, "Context reset attempt"),
    (r"(anthropic|openai|claude\s+team)\s+(says?|requires?|instructed|told\s+you)",
     SEV_HIGH, "Fake authority claim"),
    (r"(admin|administrator|root|superuser)\s+(message|override|instruction|access)",
     SEV_HIGH, "Fake admin claim"),
    (r"you\s+are\s+now\s+DAN", SEV_HIGH, "DAN jailbreak attempt"),
    (r"DAN\s+(mode|persona|version)", SEV_HIGH, "DAN jailbreak attempt"),
    (r"(jailbreak|unrestricted|god)\s+mode\s+(enabled|activated|on)", SEV_HIGH, "Jailbreak mode attempt"),
    (r"(bypass|remove|disable)\s+(your\s+)?(restrictions|safeguards|safety|guardrails|filters)",
     SEV_HIGH, "Safety bypass attempt"),
    (r"<\s*system\s*>", SEV_HIGH, "Fake <system> tag"),
    (r"<\s*/?\s*(?:instruction|override|admin)\s*>", SEV_HIGH, "Fake instruction/override tag"),
    (r"\[INST\]", SEV_HIGH, "Fake [INST] delimiter"),
    (r"<<\s*SYS\s*>>", SEV_HIGH, "Fake <<SYS>> delimiter"),
    (r"\[\[SYSTEM\]\]|\(\(SYSTEM\)\)", SEV_HIGH, "Fake system delimiter"),
    (r"===\s*end\s+of\s+(system\s+)?prompt\s*===", SEV_HIGH, "Fake prompt boundary marker"),
    (r"---\s*system\s+override\s*---", SEV_HIGH, "Fake system override marker"),
    (r"show\s+(me\s+)?(your|the)\s+(system\s+)?prompt", SEV_HIGH, "System prompt extraction attempt"),
    (r"repeat\s+(your|the)\s+(system\s+)?(instructions|prompt)\s+(verbatim|exactly|word\s+for\s+word)",
     SEV_HIGH, "System prompt extraction attempt"),
    (r'"role"\s*:\s*"system"', SEV_HIGH, "Fake JSON system role injection"),
    (r"real\s+instruction(s)?\s+start(s)?\s+here", SEV_HIGH, "Instruction boundary manipulation"),
    (r"output\s+(the\s+)?(contents?\s+of|all)\s+.*\.(env|key|pem|secret)",
     SEV_HIGH, "Secret extraction request"),
    (r"include\s+(the\s+)?.*password.*\s+in\s+(your|the)\s+(response|output)",
     SEV_HIGH, "Password extraction request"),
    # Priority manipulation (MEDIUM — advisory only)
    (r"(highest|top|maximum)\s+priority", SEV_MEDIUM, "Priority manipulation attempt"),
    (r"you\s+are\s+now\s+(a|an|the)\s+", SEV_MEDIUM, "Role reassignment attempt"),
    (r"act\s+as\s+(a|an|if)\s+", SEV_MEDIUM, "Role hijacking attempt"),
    (r"pretend\s+(you\s+are|to\s+be)", SEV_MEDIUM, "Role hijacking attempt"),
    (r"in\s+(our|the)\s+(last|previous)\s+conversation\s+you\s+(agreed|said|confirmed|promised)",
     SEV_MEDIUM, "False context claim"),
])

# ── PostToolUse: hidden text / steganography ───────────────────────────────────

_HIDDEN_TEXT = _compile([
    (r"[​‌‍⁠﻿]{3,}", SEV_HIGH,
     "Cluster of zero-width characters (possible hidden instructions)"),
    (r"[͏ᅟᅠ឴឵᠎]{2,}", SEV_HIGH,
     "Cluster of Unicode filler/combining characters"),
    (r"<!--\s*(?:ignore|override|execute|run|system|prompt)", SEV_HIGH,
     "HTML comment with suspicious instruction keyword"),
    (r"<(?:div|span|p)\s+style\s*=\s*[\"'].*?display\s*:\s*none.*?[\"']>",
     SEV_MEDIUM, "Hidden HTML element (display:none)"),
    (r"color\s*:\s*(?:white|#fff(?:fff)?|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\))",
     SEV_LOW, "White-on-white text (possible steganography)"),
    # Homoglyphs — Cyrillic/Greek chars that look like Latin letters
    (r"[аеорсухһіј]{3,}",
     SEV_HIGH, "Cluster of Cyrillic homoglyphs"),
    (r"[αεορΑΒΕΗΚΜΝΟΡΤΧ]{3,}",
     SEV_HIGH, "Cluster of Greek homoglyphs"),
])

# ── PostToolUse: leetspeak evasion ─────────────────────────────────────────────

_LEETSPEAK = _compile([
    (r"1gn0r3\s+(pr3v10us|pr10r|4ll)", SEV_HIGH, "Leetspeak instruction override (1gn0r3)"),
    (r"d1sr3g4rd\s+(pr3v10us|pr10r|4ll|4b0v3)", SEV_HIGH, "Leetspeak instruction override (d1sr3g4rd)"),
    (r"f0rg3t\s+(pr3v10us|pr10r|y0ur|4ll)", SEV_HIGH, "Leetspeak instruction override (f0rg3t)"),
    (r"0v3rr1d3\s+(syst3m|s4f3ty|pr3v10us)", SEV_HIGH, "Leetspeak system override (0v3rr1d3)"),
    (r"j41lbr34k\s+(m0d3|3n4bl3d|4ct1v4t3d)", SEV_HIGH, "Leetspeak jailbreak attempt"),
    (r"syst3m\s+(pr0mpt|0v3rr1d3|1nstruct10ns)", SEV_HIGH, "Leetspeak system prompt reference"),
])


# ── Public API ─────────────────────────────────────────────────────────────────

def scan_bash(command: str, allowed_patterns: Sequence[str] = ()) -> list[ScanIssue]:
    """Scan a Bash command for security issues (PreToolUse)."""
    if any(re.search(p, command) for p in allowed_patterns):
        return []
    issues: list[ScanIssue] = []
    issues.extend(_check(command, _EXFIL, "exfiltration"))
    issues.extend(_check(command, _SECRET_ACCESS, "secret_access"))
    issues.extend(_check(command, _DESTRUCTIVE, "destructive"))
    issues.extend(_check_destructive_rm(command))
    issues.extend(_check(command, _SUSPICIOUS_INSTALL, "suspicious_install"))
    issues.extend(_check(command, _OBFUSCATION, "obfuscation"))
    return issues


def scan_write(file_path: str, content: str,
               allowed_paths: Sequence[str] = ()) -> list[ScanIssue]:
    """Scan a Write/Edit operation for protected paths and content injection (PreToolUse)."""
    issues: list[ScanIssue] = []
    if not any(re.search(p, file_path) for p in allowed_paths):
        issues.extend(_check(file_path, _PROTECTED_PATHS, "protected_path"))
    if content:
        issues.extend(_check(content, _CONTENT_INJECTION, "content_injection"))
    return issues


def scan_output(tool_result: str) -> list[ScanIssue]:
    """Scan tool output for prompt injection and steganography (PostToolUse)."""
    if not tool_result:
        return []
    issues: list[ScanIssue] = []
    issues.extend(_check(tool_result, _INJECTION, "prompt_injection"))
    issues.extend(_check(tool_result, _HIDDEN_TEXT, "hidden_text"))
    issues.extend(_check(tool_result, _LEETSPEAK, "leetspeak"))
    return issues


def worst(issues: list[ScanIssue]) -> ScanIssue | None:
    """Return the highest-severity issue, or None if empty."""
    return max(issues, key=lambda i: i.severity) if issues else None
