# Skill Security Audit: <skill name>

Verdict: <No obvious threat / Suspicious / Unsafe / Inconclusive>
Confidence: <Low / Medium / High>
Audit mode: <Static only / Static plus limited execution>
Target: `<absolute path>`
Date: <YYYY-MM-DD>

## Executive Summary

<One short paragraph describing the main conclusion and highest-risk issue.>

## Findings

### [<Severity>] <Finding title>

- Evidence: `<file>:<line>`
- What happens: <observed behavior only>
- Why it matters: <security impact>
- Exploit conditions: <what must happen for this to be exploitable>
- Recommendation: <minimal remediation>
- Confidence: <Low / Medium / High>

## Clean Signals

- <Evidence-backed absence of common risk indicators.>

## Hashes

```text
<SHA256>  <path>
```

## Limitations

- Static analysis cannot prove absence of malware.
- <List files not inspected, tools unavailable, antivirus status, network restrictions, or binary-analysis gaps.>

## Recommended Next Steps

1. <Most important fix or validation step.>
2. <Second step.>
