# Phase 00 Release Notes

## Objective

Translate the AegisHunt research brief into implementable, testable requirements
and establish an installable, quality-gated engineering foundation without
implementing later-phase telemetry, storage, flow, or ML behavior.

## Status

Implementation complete locally - GitHub checkpoint blocked. This phase is not
`Phase complete`; its branch has not been pushed and its PR has not been created
because `gh` and `origin` are unavailable.

## Completed scope

- Complete requirements extraction from both source PDFs.
- System requirements, 16 core use cases, non-functional requirements, and architecture.
- Eight ADRs covering the required technology and research decisions.
- Python 3.11+ package, Typer CLI, FastAPI health shell, and Streamlit status page.
- Project workspaces for configuration, data, artifacts, reports, and tests.
- Ruff, strict mypy, pytest, branch-aware coverage, pre-commit, Make targets, CI, and PR template.
- Git initialization baseline, `main`, and `phase/00-foundation` with logical commits.

## Major files

- `README.md`, `pyproject.toml`, `Makefile`, `.gitignore`, `.env.example`.
- `src/aegishunt/cli.py`, `src/aegishunt/api/app.py`, `src/aegishunt/frontend/app.py`.
- `tests/unit/` smoke tests.
- `docs/system_requirements.md`, `docs/use_cases.md`,
  `docs/non_functional_requirements.md`, and `docs/architecture.md`.
- `docs/adr/0001-*.md` through `docs/adr/0008-*.md`.
- `.github/workflows/ci.yml` and `.github/pull_request_template.md`.

## Architecture changes

- Established the modular-monolith boundary and a service-oriented internal plan.
- Selected FastAPI, Streamlit, Typer, and planned SQLite/SQLAlchemy storage.
- Defined dual detection, deterministic hypothesis generation, safe PCAP replay,
  and LLM-independent core operation.
- Defined that the frontend consumes API contracts and does not directly access storage or model files.

## Commits

- `13c945a` - `build: configure Phase 0 Python project`
- `ec1132b` - `feat: add Phase 0 application shells`
- `bf90cbf` - `test: add Phase 0 smoke coverage`
- `df6fb75` - `ci: add Phase 0 quality checks`
- `86f89a0` - `docs: define requirements and architecture decisions`
- Progress/release metadata commit - pending at the time this file was authored.

The `main` baseline is `fafe98f` (`chore: initialize AegisHunt source materials`).

## Tests

- `ruff check .`: passed.
- `mypy src`: passed for eight source files.
- `pytest`: 11 passed.
- Branch-aware coverage: 97.06%.
- API `/health` and `/docs`: HTTP 200 in a live Uvicorn process.
- Streamlit: import, live health endpoint, HTTP root, and Chrome-rendered content verified.
- CI and pre-commit YAML: parsed successfully.

## Known limitations

- No Phase 1+ business logic is implemented.
- No database, PCAP parser, flow records, behavioral features, datasets, models,
  detections, alerts, hypotheses, cases, replay engine, or measured performance exists.
- No generated model, dataset, database, PCAP, or evaluation artifact is committed.
- Remote publication is blocked by missing GitHub CLI and absent `origin`.

## Migration notes

There is no prior application or data schema to migrate. Developers should use
Python 3.11+ and install from `pyproject.toml` with the `dev` extra.

## Version-control checkpoint

- Branch: `phase/00-foundation`
- Pull request: pending (blocked before creation)
- PR number: pending
- Merge commit: pending
- Tag: not created; must remain absent until merge and explicit user instruction
- Merge strategy: squash and merge

## Next phase

Phase 1 will introduce validated YAML/environment configuration, core Pydantic
schemas, SQLAlchemy entities and repositories, SQLite WAL initialization, schema
versioning, and audit logging. It has not started and must not start automatically.
