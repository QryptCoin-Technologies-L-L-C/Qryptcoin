# Incident Response Plan (QryptCoin Core)

This document describes a lightweight, repeatable incident response process for security issues affecting QryptCoin Core.
It complements `SECURITY.md` (external reporting) with internal triage and execution steps.

## Goals

- Minimize time-to-triage and time-to-fix for reported vulnerabilities.
- Coordinate disclosure responsibly and avoid unnecessary ecosystem disruption.
- Produce high-quality postmortems and preventative follow-ups.

## Roles

- **Security Lead**: owns triage decisions, disclosure strategy, and coordination.
- **Engineering Lead**: owns patch execution, review, and release readiness.
- **Release Manager**: prepares builds, tags, and release artifacts.
- **Comms Lead**: drafts public advisory and coordinates announcements.

(A small team may combine roles; responsibilities still apply.)

## Severity levels (examples)

- **Critical**: key theft, remote code execution, consensus failure, chain halt, or reliable fund loss.
- **High**: network-wide DoS, wallet signing bypass, serious privacy leak, or reliable local privilege escalation.
- **Medium**: limited DoS, information disclosure requiring unusual setup, hard-to-exploit memory safety issues.
- **Low**: minor leaks, best-practice deviations, or non-exploitable crashes.

## Triage workflow

1. **Acknowledge** reporter within 24 hours (or next business day).
2. **Reproduce** on a clean environment and identify affected versions/commits.
3. **Scope** impact: consensus safety, wallet safety, network exposure, and exploitability.
4. **Classify** severity and determine an initial disclosure timeline.
5. **Track** the issue privately (GitHub Security Advisory preferred).

## Fix workflow

1. **Mitigation first** if exploitation is active or likely (e.g., configuration guidance, temporary throttles).
2. **Patch** with minimal, reviewable changes; avoid mixing unrelated refactors.
3. **Add tests** that reproduce the issue and prevent regressions.
4. **Run validation**: unit/integration tests, static analysis, and targeted fuzzing (where applicable).
5. **Prepare advisory**: description, impact, affected versions, mitigation steps, and credits.
6. **Release**: tag, build artifacts, publish advisory, and announce according to severity.

## Communication & coordination

- **Pre-disclosure**: coordinate privately with critical ecosystem partners when necessary (severity-based).
- **Public disclosure**: publish advisory with clear upgrade guidance and mitigations.
- **Postmortem**: publish a root-cause analysis when appropriate (excluding sensitive exploit details if needed).

## Evidence retention

- Preserve minimal reproduction cases, crash logs, and relevant telemetry.
- Retain private discussions and patch review references in the advisory.

## Post-incident follow-ups

- Add/expand fuzzers or property-based tests for the affected surface.
- Update the threat model (`docs/security/threat-model.md`) if assumptions changed.
- Consider hardening defaults or adding new instrumentation to detect recurrence.

