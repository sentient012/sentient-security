# Security policy

## Reporting a vulnerability

Please report privately through GitHub's **private vulnerability reporting**:
<https://github.com/sentient012/sentient-security/security/advisories/new>.
Do not open a public issue for a suspected vulnerability.

Include the affected subpath and version, a description, and, where possible, a
reproducing test (a failing `node:test` case is ideal).

What to expect:
- An acknowledgement within 5 business days.
- An assessment and planned fix timeline within 30 days.
- Coordinated disclosure. We aim to publish a fix and advisory within 90 days
  of the report, sooner for actively exploited issues. We credit reporters who
  want credit.

There is **no bug bounty** at this time, and we cannot offer payment.

## Safe-harbour guidelines

Testing this package locally (unit tests, fuzzing, reading the code) is
welcome and needs no permission. Do **not** test against Sentient's production
service, other people's accounts or real users' data. Do not run load or
denial-of-service tests against our infrastructure. We will not pursue
action against good-faith research that follows these rules.

## Supported versions

| Version | Supported |
|---|---|
| 0.4.x | Yes (current; used by Sentient 4.2.0) |
| 0.1.x – 0.3.x | Fixes are released as 0.4.x |

## Scope

In scope: the code in this repository, its build output, and the
correctness of claims in README.md, THREAT_MODEL.md, PROTOCOLS.md and
docs/session-protocols.md.
Out of scope: Sentient's server, apps and infrastructure. You may still report
issues there privately through the same channel, but this repository's code
does not implement them.
