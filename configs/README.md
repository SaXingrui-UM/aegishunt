# Configuration

`application.yaml` contains safe, version-controlled defaults. Environment
variables prefixed with `AEGISHUNT_` override YAML values by using a double
underscore for nested keys, for example `AEGISHUNT_DATABASE__URL`.

Secrets must not be committed to YAML. Use process environment variables or a
local ignored `.env` file managed outside AegisHunt.

The `ingestion` section controls the upload storage root, reviewed sample root,
maximum upload size, stream chunk size, and maximum record count. Paths are
configuration values rather than code constants. Do not point the upload root
at a source directory or a shared executable location.

The `datasets` section controls the registry and label-mapping locations;
raw/interim/processed/report roots; download and expanded-archive limits;
near-duplicate tolerance; controlled-demo seed; and train/validation/test ratios.
Ratios must sum to `1.0`. Raw and processed datasets are local artifacts and must
not be committed. Public acquisition remains explicit and license-aware.
