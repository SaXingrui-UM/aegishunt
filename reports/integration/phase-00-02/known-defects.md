# Phase 0–2 Integration Verification Defects

Open counts: Blocking 0, High 0, Medium 2, Low 1.
Resolved during verification: High 2.

## DEF-001 — JSONL uploads lost their format during staging

- Severity: High
- Status: Resolved
- Component: ingestion file staging / JSON event adapter
- Initial evidence: the first new verification run collected 26 targeted tests;
  25 passed and `test_cli_ingests_pcap_csv_json_and_allowlisted_sample` failed.
- Steps: ingest a valid two-line `.jsonl` file through the CLI or service.
- Expected: the JSON Lines adapter validates both records and completes the job.
- Actual before fix: the extensionless staging file was treated as one JSON document;
  parsing failed at line 2 and the job could not complete.
- Root cause: `mkstemp` created an extensionless staging path, while the JSON adapter
  selects JSON versus JSONL parsing from the path suffix.
- Fix: preserve the already validated extension on the temporary staging file.
- Fix commit: `60420973f13b829b2a9395c166d8975d2a075a13`
- Regression evidence: CLI JSONL coverage in
  `tests/e2e/test_phase_00_02_integration.py`; final 72-test suite passes.

## DEF-002 — Database credentials appeared in settings repr

- Severity: High
- Status: Resolved
- Component: configuration secret redaction
- Steps: construct settings with `sqlite://user:password@localhost/...` and call
  `repr(settings)` or `repr(settings.database)`.
- Expected: credentials are absent from diagnostic representations.
- Actual before fix: the URL, including `password`, was present.
- Root cause: the Pydantic database URL field used the default representation behavior.
- Fix: mark `DatabaseSettings.url` with `repr=False`.
- Fix commit: `b20a467df190dd9b1971524750c340d3447ca6df`
- Regression evidence: `test_database_url_is_redacted_from_settings_repr`; final
  API `/health`, CLI errors, and representations contain no tested secret.

## DEF-003 — Doctor omits configuration and database status

- Severity: Medium
- Status: Open
- Component: Phase 0 CLI diagnostics
- Steps: run `aegishunt doctor` in an installed project.
- Expected for this verification contract: Python, directories, configuration,
  and database status are reported without secrets.
- Actual: exit code is correct and Python/OS/machine/directories are reported,
  but no configuration or database-status fields exist.
- Evidence: P0-003 in `test-matrix.csv` and the clean-clone doctor output.
- Phase 3 impact: non-blocking for packet-to-flow work, but reduces operator diagnostics.

## DEF-004 — Database outage is fail-closed but not durably traceable

- Severity: Medium
- Status: Open
- Component: ingestion API/database failure handling
- Steps: inject a controlled session-construction failure and upload valid telemetry.
- Expected for P2-NEG-019: rollback, no completed job, a safe response, and traceable failure state.
- Actual: rollback succeeds and no job is committed or falsely completed; the API emits
  a generic HTTP 500, but cannot persist a failed job while the database is unavailable.
- Evidence: `test_database_failure_is_generic_and_never_commits_a_job` and P2-NEG-019.
- Phase 3 impact: non-blocking for local flow extraction, but runtime observability needs a
  later out-of-band or recovery design rather than a broad change in this verification task.

## DEF-005 — README names the merged Phase 2 branch as current

- Severity: Low
- Status: Open
- Component: documentation accuracy
- Steps: read the README `Current status` section on current `main`.
- Expected: Phase 2 is described as merged/completed on `main`.
- Actual: it says Phase 2 is implemented on `phase/02-telemetry-ingestion`.
- Evidence: P0-009 in `test-matrix.csv`.
- Phase 3 impact: none; fix in a focused documentation change after this independent verification.

## Informational Limitations

- Wheel verification was not executed because `build` is not a declared dependency.
- The first clean-clone install command was interrupted by the execution harness before
  installation completed; the unchanged command succeeded on retry and a second new clone
  then installed and passed all checks on its first attempt. This is not classified as a product defect.
