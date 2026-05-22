# Audit Skill Security

A Codex skill for reviewing other Codex skills and skill-like folders from a security research perspective.

It helps an agent answer questions such as:

- Does this skill contain suspicious code or prompt instructions?
- Could it leak credentials or workspace files?
- Does it execute shell commands, install dependencies, or contact the network?
- Are there risky parser patterns such as unsafe archive extraction or deserialization?
- What evidence supports the final security verdict?

## What It Includes

- `SKILL.md` - the main Codex skill workflow.
- `scripts/static_skill_audit.py` - a read-only static triage scanner.
- `references/risk-taxonomy.md` - severity guidance for security findings.
- `references/report-template.md` - a structured audit report template.
- `agents/openai.yaml` - UI metadata for Codex skill discovery.

## Quick Start

Run the static scanner against a skill directory:

```powershell
python scripts/static_skill_audit.py "C:\Users\you\.codex\skills\some-skill" --format markdown
```

For machine-readable output:

```powershell
python scripts/static_skill_audit.py "C:\Users\you\.codex\skills\some-skill" --format json
```

The scanner reports suspicious patterns with file and line evidence, hashes files for reproducibility, and avoids executing target code.

## Recommended Audit Flow

1. Inspect metadata and directory structure first.
2. Run `static_skill_audit.py` for triage.
3. Manually review each finding for reachability and intent.
4. Classify severity using `references/risk-taxonomy.md`.
5. Write the final report using `references/report-template.md`.

## Safety Model

This project is designed for defensive review. It defaults to static analysis and treats target skill content as untrusted.

It does not:

- execute target skill scripts,
- install target skill dependencies,
- upload files,
- delete or quarantine files,
- prove that a skill is malware-free.

Static analysis can find common risk indicators, but it cannot prove the absence of malicious behavior. Use antivirus, sandboxing, and manual code review when stronger assurance is required.

## Installing As A Codex Skill

Place this folder under your Codex skills directory, for example:

```text
C:\Users\you\.codex\skills\audit-skill-security
```

Then ask Codex to use `$audit-skill-security` when reviewing a skill folder.

## License

No license has been specified yet. Add one before distributing or accepting external contributions.
