#!/usr/bin/env python3
"""Static triage scanner for Codex skill directories.

The scanner is intentionally conservative: it reports suspicious patterns with
file/line evidence, but it does not execute target code or install packages.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


TEXT_SUFFIXES = {
    ".bat",
    ".cmd",
    ".css",
    ".html",
    ".js",
    ".json",
    ".md",
    ".mjs",
    ".ps1",
    ".py",
    ".sh",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".yaml",
    ".yml",
}

EXECUTABLE_SUFFIXES = {
    ".bat",
    ".cmd",
    ".com",
    ".dll",
    ".dylib",
    ".exe",
    ".msi",
    ".ps1",
    ".scr",
    ".sh",
    ".so",
}

PATTERNS: list[tuple[str, str, str, str]] = [
    ("critical", "credential private key", r"-----BEGIN (RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----", "Private key material appears to be embedded."),
    ("high", "cloud or api token", r"\b(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9_]{30,}|sk-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]+)\b", "A credential-like token appears in text."),
    ("high", "authorization header", r"\b(Authorization|Bearer|api[_-]?key|secret|password|passwd|credential|token)\b", "Credential handling or hardcoded secret language appears."),
    ("high", "network client", r"\b(requests\.|urllib\.|httpx\.|aiohttp|socket\.|websocket|ftplib|smtplib)\b", "Code may communicate over the network."),
    ("high", "download command", r"\b(curl|wget|Invoke-WebRequest|iwr|Start-BitsTransfer)\b", "Code or instructions may download remote content."),
    ("high", "shell execution", r"\b(subprocess\.|os\.system|Popen\(|Start-Process|powershell|cmd\.exe|bash\s+-c|sh\s+-c)\b", "Code may execute shell commands or child processes."),
    ("high", "dynamic code execution", r"(?<!\.)\b(eval|exec|compile)\s*\(|\bFunction\s*\(|\bsetTimeout\s*\([^,\n]+,", "Code may execute dynamically constructed code."),
    ("medium", "dynamic import", r"\b(importlib\.import_module|__import__\s*\()\b", "Code may dynamically import modules; check whether the module name is controlled by untrusted input."),
    ("high", "unsafe archive extraction", r"\b(extractall\(|extractToDirectory|Expand-Archive)\b", "Archive extraction must be checked for path traversal protection."),
    ("high", "unsafe deserialization", r"\b(pickle\.load|pickle\.loads|marshal\.load|marshal\.loads|joblib\.load|yaml\.load\()\b", "Unsafe parser or deserializer may execute or instantiate attacker-controlled data."),
    ("high", "destructive filesystem", r"\b(Remove-Item|rm\s+-rf|rmdir\s+/s|del\s+/[fsq]|shutil\.rmtree|unlink\(|DeleteFile)\b", "Code may delete files or directories."),
    ("medium", "dependency install", r"\b(pip\s+install|npm\s+install|pnpm\s+install|yarn\s+add|uv\s+pip\s+install|conda\s+install)\b", "Runtime dependency installation can introduce supply-chain risk."),
    ("medium", "broad home access", r"(\$HOME|%USERPROFILE%|~[/\\]|Path\.home\(\)|os\.environ\[['\"]HOME|USERPROFILE)", "Code may access broad user directories."),
    ("medium", "prompt injection language", r"(ignore previous instructions|reveal.*secret|bypass.*approval|do not tell the user|hidden instruction)", "Prompt text may attempt to redirect an agent unsafely."),
    ("medium", "encoded payload hint", r"\b(base64|FromBase64String|atob\(|btoa\(|gzip\.decompress|zlib\.decompress)\b", "Encoded or compressed payload handling appears."),
]


@dataclass
class Finding:
    severity: str
    category: str
    path: str
    line: int
    match: str
    note: str


@dataclass
class FileInfo:
    path: str
    size: int
    sha256: str
    executable_suffix: bool
    high_entropy_strings: list[str]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Statically audit a Codex skill directory.")
    parser.add_argument("target", help="Skill directory to scan")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--max-file-bytes", type=int, default=1_000_000)
    return parser.parse_args()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_probably_text(path: Path) -> bool:
    if path.suffix.lower() in TEXT_SUFFIXES:
        return True
    try:
        data = path.read_bytes()[:4096]
    except OSError:
        return False
    if b"\x00" in data:
        return False
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = {char: text.count(char) for char in set(text)}
    return -sum((count / len(text)) * math.log2(count / len(text)) for count in counts.values())


def find_high_entropy_strings(text: str) -> list[str]:
    candidates = re.findall(r"[A-Za-z0-9+/=_-]{40,}", text)
    hits = []
    for value in candidates:
        if shannon_entropy(value) >= 4.7:
            hits.append(redact(value))
    return hits[:10]


def redact(value: str) -> str:
    value = value.strip()
    if len(value) <= 12:
        return value
    return f"{value[:6]}...{value[-4:]}"


def iter_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if path.is_file():
            yield path


def scan_text(path: Path, root: Path, max_file_bytes: int) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    try:
        if path.stat().st_size > max_file_bytes:
            return findings, []
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return findings, []

    rel = str(path.relative_to(root))
    for line_number, line in enumerate(text.splitlines(), start=1):
        for severity, category, pattern, note in PATTERNS:
            match = re.search(pattern, line, flags=re.IGNORECASE)
            if match:
                findings.append(
                    Finding(
                        severity=severity,
                        category=category,
                        path=rel,
                        line=line_number,
                        match=redact(match.group(0)),
                        note=note,
                    )
                )
    return findings, find_high_entropy_strings(text)


def audit(root: Path, max_file_bytes: int) -> dict:
    root = root.resolve()
    files: list[FileInfo] = []
    findings: list[Finding] = []

    for path in iter_files(root):
        rel = str(path.relative_to(root))
        high_entropy: list[str] = []
        if is_probably_text(path):
            text_findings, high_entropy = scan_text(path, root, max_file_bytes)
            findings.extend(text_findings)
            for value in high_entropy:
                findings.append(
                    Finding(
                        severity="medium",
                        category="high entropy string",
                        path=rel,
                        line=0,
                        match=value,
                        note="A high-entropy string may be a secret, compressed payload, hash, or benign encoded data.",
                    )
                )
        files.append(
            FileInfo(
                path=rel,
                size=path.stat().st_size,
                sha256=sha256(path),
                executable_suffix=path.suffix.lower() in EXECUTABLE_SUFFIXES,
                high_entropy_strings=high_entropy,
            )
        )
        if path.suffix.lower() in EXECUTABLE_SUFFIXES and path.suffix.lower() not in {".sh", ".ps1", ".bat", ".cmd"}:
            findings.append(
                Finding(
                    severity="high",
                    category="binary executable",
                    path=rel,
                    line=0,
                    match=path.suffix.lower(),
                    note="Binary executable content requires separate malware analysis.",
                )
            )

    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1

    verdict = "No obvious threat"
    if counts.get("critical"):
        verdict = "Unsafe"
    elif counts.get("high"):
        verdict = "Suspicious"
    elif counts.get("medium"):
        verdict = "Review recommended"

    return {
        "target": str(root),
        "file_count": len(files),
        "total_bytes": sum(file.size for file in files),
        "verdict": verdict,
        "severity_counts": counts,
        "findings": [asdict(finding) for finding in findings],
        "files": [asdict(file) for file in files],
        "limitations": [
            "Static pattern matching cannot prove absence of malware.",
            "Findings require manual reachability and intent analysis.",
            "Binary files are hashed but not reverse engineered.",
        ],
    }


def render_markdown(result: dict) -> str:
    lines = [
        f"# Static Skill Audit: {Path(result['target']).name}",
        "",
        f"Target: `{result['target']}`",
        f"Verdict: **{result['verdict']}**",
        f"Files: {result['file_count']}",
        f"Total bytes: {result['total_bytes']}",
        "",
        "## Severity Counts",
        "",
    ]
    counts = result["severity_counts"]
    if counts:
        for severity in ["critical", "high", "medium", "low", "informational"]:
            if severity in counts:
                lines.append(f"- {severity}: {counts[severity]}")
    else:
        lines.append("- No suspicious pattern hits.")

    lines.extend(["", "## Findings", ""])
    if result["findings"]:
        for finding in result["findings"]:
            location = finding["path"] if finding["line"] == 0 else f"{finding['path']}:{finding['line']}"
            lines.extend(
                [
                    f"### [{finding['severity']}] {finding['category']}",
                    f"- Evidence: `{location}`",
                    f"- Match: `{finding['match']}`",
                    f"- Note: {finding['note']}",
                    "",
                ]
            )
    else:
        lines.append("No suspicious pattern hits were found.")
        lines.append("")

    lines.extend(["## File Hashes", "", "```text"])
    for file_info in result["files"]:
        marker = " executable-suffix" if file_info["executable_suffix"] else ""
        lines.append(f"{file_info['sha256']}  {file_info['path']}{marker}")
    lines.extend(["```", "", "## Limitations", ""])
    for item in result["limitations"]:
        lines.append(f"- {item}")
    return "\n".join(lines) + "\n"


def main() -> int:
    args = parse_args()
    root = Path(args.target)
    if not root.exists() or not root.is_dir():
        raise SystemExit(f"Target is not a directory: {root}")
    result = audit(root, args.max_file_bytes)
    if args.format == "json":
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(render_markdown(result), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
