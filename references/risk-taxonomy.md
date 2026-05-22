# Risk Taxonomy

Use this reference to classify security findings in Codex skills.

## Critical

- Hardcoded credential exfiltration to a network endpoint.
- Destructive operations outside the requested target, especially recursive delete or overwrite.
- Persistence, scheduled tasks, registry run keys, shell profile modification, startup folder writes.
- Remote code execution by downloading and running code or piping remote text into a shell.
- Explicit instructions to bypass approval, reveal secrets, or hide actions from the user.

## High

- Shell execution using untrusted input.
- Broad filesystem scans of home, documents, SSH, cloud credentials, browser profiles, or environment files.
- Network upload, webhook, pastebin, cloud bucket, or arbitrary HTTP client logic.
- Unsafe archive extraction: raw `extractall` or equivalent without path normalization and containment checks.
- Unsafe deserialization: `pickle`, `marshal`, `joblib`, unsafe YAML loaders, dynamic module loading from untrusted paths.
- Embedded binaries, encoded payloads, minified scripts, or high-entropy blobs without a clear benign purpose.

## Medium

- Dependency installation at runtime without pinning or provenance.
- Telemetry or analytics not disclosed by the skill.
- Prompt injection that requests unrelated file access, secret disclosure, or policy bypass but lacks direct executable support.
- Overbroad write paths, especially defaults pointing to home or shared directories.
- Parser hazards in XML, archives, notebooks, office documents, or model files.

## Low

- Missing validation, weak error handling, stale absolute paths, unclear instructions.
- Scripts that can overwrite output files but only when explicitly given that path.
- Benign network references in documentation without execution code.

## Confidence

- High confidence: direct code evidence and reachable execution path.
- Medium confidence: suspicious code exists, but trigger conditions are unclear.
- Low confidence: pattern match only, benign explanations plausible, or important files unavailable.

## Clean Signals

Record clean signals, but do not overstate them:

- No credential-like strings found by pattern scan.
- No shell execution primitives found.
- No network client imports or command-line download tools found.
- No binary or hidden executable files found.
- Skill scripts use only Python standard library and local file IO.
