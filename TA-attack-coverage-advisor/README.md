# TA-attack-coverage-advisor

Splunk TA for a sales-engineering ATT&CK coverage conversation:

- inventory customer telemetry actually indexed on the search head,
- compare that telemetry to the Splunk `security_content` detection catalog,
- expose current enabled ES coverage when ES is installed,
- surface activable but non-enabled content,
- highlight missing strategic sources and their projected ATT&CK unlock.

The TA is intentionally V1: pragmatic, self-contained, and credible enough for customer workshops and internal challenge sessions.

## Operator Documentation

For the explicit French technical user guide used by SE / partner / consulting populations, see:

- `../docs/dsa-assessment-technical-guide-en.md`

For the installation and deployment procedure, see:

- `INSTALLATION.md`

These guides explain:

- what is observed now vs projected with ES,
- how to read the degraded `DSA++ classique` mode,
- how to interpret the dashboard and search command outputs,
- how to run a credible customer assessment workshop,
- how to install the app through Splunk Web or direct filesystem deployment.

## What It Ships

- `bin/attack_coverage_advisor.py`
  - custom generating search command `attackcoverageadvisor`
- `bin/attack_coverage_catalog_builder.py`
  - helper script to regenerate embedded lookup CSVs from a local `security_content` clone
- `bin/validate_local.py`
  - local validation helper for syntax, package structure, and catalog regeneration
- `lookups/attack_coverage_data_sources.csv`
  - normalized data source catalog generated from `security_content/data_sources/*.yml`
- `lookups/attack_coverage_detections.csv`
  - normalized detection catalog generated from `security_content/detections/**/*.yml`
- `lookups/attack_coverage_detection_data_sources.csv`
  - flattened detection-to-data-source mapping

Runtime does not require internet access. The packaged CSVs are embedded in the TA, and `splunklib` is vendored under `bin/lib/` so the search command stays portable on a Splunk search head.

## Architecture

### 1. Indexed data source inventory

The command uses Splunk-native metadata searches on the search head:

- `| metadata type=sourcetypes ...`
- `| metadata type=sources ...`

Observed `sourcetype` and `source` values are matched to the embedded `security_content` data source catalog.

### 2. Current and potential coverage

If Enterprise Security is installed, the command checks:

- app presence via `| rest /services/apps/local`
- enabled correlation searches via `| rest /servicesNS/-/-/saved/searches`

Enabled detections are name-matched against the bundled `security_content` snapshot, then enriched from live `action.correlationsearch.annotations` when ATT&CK technique IDs are present.

Potential coverage is calculated from catalog detections that are not currently active:

- `activable`
  - all mapped data sources are already present
- `partial`
  - some mapped data sources are present, but companion telemetry may still be missing

If ES is not installed, the command degrades to a what-if mode and answers:

- what would be activable if ES content were adopted,
- which telemetry gaps would unlock the next ATT&CK steps.

### 3. Strategic gaps

For each missing catalog data source, the command estimates:

- detections that would become immediately ready if that source were onboarded,
- additional detections where it would be a strong contributing source,
- ATT&CK technique IDs associated with that missing telemetry.

This is intentionally directional, not a contractual readiness engine.

## Search Command

### Syntax

```spl
| attackcoverageadvisor mode=<summary|inventory|current|potential|gaps|full> index=<*> earliest=<-30d> latest=<now> limit=<25> include_partial=<true|false> include_experimental=<true|false>
```

`include_experimental=true` only has an effect if the embedded lookup snapshot was generated with `--include-experimental`.

### Modes

- `summary`
  - compact roll-up for current posture, potential unlock, and strategic gaps
- `inventory`
  - observed mapped data sources present in indexed telemetry
- `current`
  - enabled ES detections mapped to the bundled catalog
- `potential`
  - non-active detections that current telemetry could support
- `gaps`
  - missing telemetry sources ranked by ATT&CK expansion potential
- `full`
  - summary + inventory + current + potential + gaps

### Suggested SPL

```spl
| attackcoverageadvisor mode=summary
```

```spl
| attackcoverageadvisor mode=current limit=100
| table detection_name mitre_attack_ids technique_count reason
```

```spl
| attackcoverageadvisor mode=potential include_partial=true limit=50
| table status detection_name data_source_name technique_count reason recommendation
```

```spl
| attackcoverageadvisor mode=gaps limit=20
| table data_source_name technique_count detection_count reason recommendation supported_ta_names
```

```spl
| attackcoverageadvisor mode=full index=main,summary earliest=-90d
| table section status family data_source_name detection_name mitre_attack_ids technique_count reason recommendation
```

## Output Fields

Core fields are stable across modes:

- `section`
- `status`
- `family`
- `data_source_name`
- `detection_name`
- `mitre_attack_ids`
- `technique_count`
- `reason`
- `recommendation`

Additional helper fields:

- `scenario`
- `es_installed`
- `matched_data_source_count`
- `required_data_source_count`
- `match_ratio`
- `detection_count`
- `supported_ta_names`
- `supported_ta_versions`
- `catalog_status`
- `inventory_match`
- `search_window`

## Local Validation

```bash
python3 TA-attack-coverage-advisor/bin/validate_local.py \
  --app-root TA-attack-coverage-advisor \
  --security-content /tmp/security_content
```

## Lookup Regeneration

Default source path is `/tmp/security_content`.

```bash
python3 TA-attack-coverage-advisor/bin/attack_coverage_catalog_builder.py \
  --security-content /tmp/security_content \
  --output-dir TA-attack-coverage-advisor/lookups
```

To also include experimental detections in the packaged catalog:

```bash
python3 TA-attack-coverage-advisor/bin/attack_coverage_catalog_builder.py \
  --security-content /tmp/security_content \
  --output-dir TA-attack-coverage-advisor/lookups \
  --include-experimental
```

## Limits

- Active ES mapping still starts from a bundled `security_content` name match. Live `action.correlationsearch.annotations` improves ATT&CK fidelity, but custom detections outside the catalog can still remain only partially represented.
- `partial` means at least one mapped source is present, not that every prerequisite is proven.
- Gap ranking is directional. Some detections associated with a missing source may still require additional telemetry.
- Inventory relies on `metadata` visibility for the executing user.
- ES current-state analysis relies on REST visibility for saved searches.
- This V1 does not inspect custom customer detection content outside the name-matched bundled catalog.

## Packaging Notes

- Search head native
- No runtime internet dependency
- No modification of unrelated apps required
- Generated lookups are embedded so the TA remains portable
- `splunklib` is vendored under `bin/lib/` for runtime portability

## References

- Splunk ES detection annotations: https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.2/detections/add-annotations-to-detections-in-splunk-enterprise-security
- Splunk Security Essentials MITRE dashboard logic: https://help.splunk.com/en/splunk-enterprise-security-8/security-essentials/use-splunk-security-essentials/3.8/use-the-analytics-advisor-in-splunk-security-essentials/the-mitre-attck-framework-dashboard
