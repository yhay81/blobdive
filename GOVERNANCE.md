# Governance

BlobDive is maintained in public.

## Roles

- **Contributors** propose issues, fixtures, docs, tests, adapters, and reviews.
- **Maintainers** triage reports, protect public contracts and safety claims,
  manage security responses, and define releases.
- **Release managers** are maintainers authorized to create signed tags and
  trigger release automation.

The repository owner is the current maintainer and release manager. New
maintainers may be added after sustained constructive contributions and
demonstrated understanding of parser boundaries, adversarial fixtures,
resource accounting, and schema compatibility.

## Decision process

Small reversible changes are decided through pull requests. New structural
adapters, reference/schema changes, parser isolation, external backends,
dependency policy, and security-boundary changes start with an issue and remain
open for public feedback.

Decisions favor:

1. bounded evidence over format-coverage claims;
2. no materialization or execution;
3. explicit truncation and parser limitations;
4. stable machine-readable contracts;
5. synthetic adversarial fixtures and reproducible corpus metrics.

If consensus is not reached, a maintainer records the decision and rationale.
Security-sensitive details remain private until coordinated disclosure.

## Changes and releases

Contributor pull requests need maintainer approval. Maintainer-authored pull
requests need a recorded self-review and all required checks. Release
requirements are in [RELEASING.md](RELEASING.md).

## Project health

Maintainers periodically review dependency freshness, unanswered reports,
cross-platform and adversarial failures, corpus accuracy, budget guarantees,
schema compatibility, release reproducibility, security reports, and opt-in
adoption.

## Continuity

The project currently has one repository owner and one release-capable
maintainer. [MAINTAINER_CONTINUITY.md](MAINTAINER_CONTINUITY.md) records the
unmitigated authority risks, fail-closed signing-key rotation, and a monthly
public recovery drill. A green drill does not substitute for a second
maintainer or restore private repository state.
