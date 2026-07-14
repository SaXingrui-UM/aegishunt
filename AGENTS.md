 # AGENTS.md

## Project

AegisHunt
Design and Implementation of an Autonomous Threat Hunting System Using Machine Learning

## Source of Truth

* `AegisHunt Project Plan.pdf` defines the overall system requirements.
* `AegisHunt Implementation Roadmap.pdf` defines phase order and acceptance criteria.
* `docs/codex_progress.md` records current implementation status.
* Never claim a planned feature is implemented unless code and tests exist.

## Phase Discipline

* Work on only one declared phase at a time.
* Do not implement later-phase functionality prematurely.
* Read `docs/codex_progress.md` before making changes.
* At the end of every phase, update progress and release documentation.
* Stop after creating the phase pull request.
* Never start the next phase automatically.

## Git Branch Policy

* `main` is the protected stable branch.
* Never develop directly on `main`.
* Use one branch per phase:

```text
phase/00-foundation
phase/01-data-foundation
phase/02-telemetry-ingestion
phase/03-flow-feature-engineering
phase/04-dataset-quality
phase/05-supervised-detection
phase/06-anomaly-detection
phase/07-fusion-evaluation
phase/08-alert-explainability
phase/09-hypothesis-engine
phase/10-case-feedback
phase/11-runtime-replay
phase/12-api-frontend
phase/13-hardening
phase/14-final-delivery
```

* Before creating a phase branch:

  * confirm the working tree is clean;
  * checkout `main`;
  * pull with `--ff-only`;
  * create the declared phase branch.
* Never push directly to `main`.

## Commit Policy

Use Conventional Commits:

```text
chore:
docs:
feat:
fix:
refactor:
test:
perf:
build:
ci:
```

Rules:

* Keep commits small and logically focused.
* Review staged changes before committing.
* Do not commit failing code.
* Do not combine unrelated changes.
* Do not use meaningless messages.
* Do not amend or rewrite pushed commits unless the user explicitly requests it.
* Do not commit generated datasets, model binaries, databases, large PCAPs, secrets, or `.env`.

## Required Checks

Before each significant commit, run relevant tests.

Before completing a phase, run:

```bash
ruff check .
mypy src
pytest
```

Also run any phase-specific integration or end-to-end checks.

A phase cannot be marked complete while required checks fail.

## Review Policy

Before pushing a completed phase:

1. Review `git diff main...HEAD`.
2. Review uncommitted changes.
3. Run Codex `/review` against `main`.
4. Focus on:

   * correctness;
   * security;
   * requirement compliance;
   * missing tests;
   * accidental secrets;
   * generated or oversized files;
   * data leakage;
   * model-evaluation integrity;
   * scope creep.
5. Fix blocking findings.
6. Re-run all required checks.
7. Commit fixes separately.

## Push and Pull Request Policy

* Push only the current phase branch.
* Never force-push.
* Create one pull request per phase.
* PR base must be `main`.
* PR title format:

```text
[Phase XX] Phase title
```

* Complete the pull-request template.
* Include tests, architecture decisions, limitations, and manual verification.
* Do not merge the pull request automatically.
* Stop and wait for user review.

## Merge Policy

* Default strategy: Squash and merge.
* Only merge after explicit user approval.
* Do not bypass failing CI or unresolved blocking reviews.
* Do not delete the remote branch unless the user requests it.

## Tag Policy

After a phase PR is merged into `main`, create an annotated checkpoint tag only when instructed:

```text
phase-00-complete
phase-01-complete
...
phase-14-complete
```

* Tags must point to merged `main`.
* Never overwrite or move an existing tag.
* Never create a completion tag before merge.

## Release Documentation

Every phase must have:

```text
docs/releases/phase-XX.md
```

Include:

* objective;
* completed scope;
* architecture decisions;
* commits;
* tests;
* known limitations;
* PR;
* merge commit;
* tag;
* next phase.

## Prohibited Git Operations

Never execute without explicit user instruction:

```bash
git reset --hard
git clean -fd
git push --force
git push --force-with-lease
git tag -f
git branch -D
git filter-branch
git filter-repo
```

Never:

* discard user changes;
* rewrite remote history;
* push directly to main;
* commit secrets;
* bypass branch protection;
* merge a PR automatically;
* claim a push, PR, merge, or tag succeeded without verifying it.

## Failure Handling

If GitHub authentication or permissions are unavailable:

* keep valid local commits;
* report the exact failure;
* provide the exact commands the user should run;
* do not claim remote operations succeeded;
* do not abandon or delete local work.

## Phase Completion Status

Before PR merge:

```text
Implementation complete — awaiting PR review
```

After PR merge and checkpoint tag:

```text
Phase complete
```
