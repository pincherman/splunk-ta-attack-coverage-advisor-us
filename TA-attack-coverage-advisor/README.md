# DSA++ Maturity Accelerator

Splunk TA and Dashboard Studio app for DSA++ workshops with existing Splunk customers.

The goal is to reproduce the team DSA++ method inside Splunk: start from the PvP/risk conversation, objectify the data sources already indexed, map them to Enterprise Security OOTB detections and MITRE ATT&CK, then produce a prioritized collection roadmap and sizing context.

This is not a contractual coverage engine and not a pricing tool. It is an SE workshop accelerator for DSA++, ES discovery, pre-POC qualification, partner workshops and maturity conversations.

> Documentation française d’usage : see [`GUIDE_UTILISATION_FR.md`](GUIDE_UTILISATION_FR.md) for the SE workshop playbook, interpretation rules, customer talk-track, guardrails and SPL examples.

## Positioning

The app answers six customer-facing questions:

1. **What risks and SOC use cases should we discuss first?**
2. **Which security data sources are already visible in Splunk?**
3. **Which Splunk Enterprise Security detections become credible with the current telemetry?**
4. **Which MITRE ATT&CK techniques/tactics are covered or blocked?**
5. **Which missing sources unlock the most detection value?**
6. **What ingestion profile should frame the sizing and roadmap discussion?**

The desired message is not “you need more GB/day”. The desired message is:

> Your current Splunk data already contains security value. DSA++ shows how Enterprise Security can operationalize it into detections, investigation, triage, risk-based alerting and a realistic roadmap.

## What It Ships

- `bin/attack_coverage_advisor.py`
  - generating search command `attackcoverageadvisor`
- `default/data/ui/views/attack_coverage_advisor_command_center.xml`
  - Dashboard Studio v2 view `attack_coverage_advisor_command_center`
- `bin/attack_coverage_catalog_builder.py`
  - helper script to regenerate embedded lookup CSVs from a local `security_content` clone
- `bin/validate_local.py`
  - local syntax, package and catalog validation helper
- `lookups/*.csv`
  - embedded catalog derived from Splunk `security_content`
- `bin/lib/splunklib/`
  - vendored Splunk SDK dependency for runtime portability

Runtime does not require internet access.

## Dashboard Tabs

- **Maturité DSA++** — workshop storyline: PvP, risk questions, data proof, decision guide.
- **Sources** — observed sources versus sources to integrate, with TA/CIM actions.
- **Règles ES** — ES OOTB rules that are activable or close to activable.
- **MITRE** — projected ATT&CK techniques and tactics, explained for the customer conversation.
- **Roadmap** — missing sources prioritized by detections and ATT&CK value unlocked.
- **Sizing** — observed ingestion trend and statistics to frame collection and architecture discussions.

## Search Command

```spl
| attackcoverageadvisor mode=<summary|inventory|current|potential|gaps|full> index=<*> earliest=<-30d> latest=<now> limit=<25> include_partial=<true|false> include_experimental=<true|false>
```

Examples:

```spl
| attackcoverageadvisor mode=summary
```

```spl
| attackcoverageadvisor mode=potential include_partial=true limit=50
| table status detection_name data_source_name technique_count reason recommendation
```

```spl
| attackcoverageadvisor mode=gaps limit=20
| table data_source_name technique_count detection_count supported_ta_names recommendation
```

## Modes

- `summary` — compact roll-up for the dashboard and executive storyline.
- `inventory` — observed mapped data sources present in indexed telemetry.
- `current` — enabled ES correlation searches mapped to the bundled catalog when ES is installed and accessible.
- `potential` — ES detections not active today but supported or partly supported by current telemetry.
- `gaps` — missing telemetry sources ranked by potential detection/ATT&CK value.
- `full` — summary + inventory + current + potential + gaps.

## Important Interpretation Rules

- **Observed now** means telemetry actually visible through Splunk metadata on the search head.
- **Projected with ES** means catalog-based value estimation from Splunk `security_content` mappings.
- **Activable** means mapped data sources are visible; the detection still needs validation, tuning and ownership before production.
- **Partial** means at least one mapped source is present; it does not prove every prerequisite is production-ready.
- `current` ES coverage is directional. It uses enabled correlation searches, catalog name matching and live ES annotations when present.
- Customer custom detections outside the bundled catalog may be partially represented or unmapped.
- Results are **directional and workshop-oriented**, not contractual coverage or licensing commitments.
- Pricing/licensing belongs with the RSM. Implementation plans belong with PS when they become project commitments.

## Local Validation

```bash
python3 TA-attack-coverage-advisor/bin/validate_local.py \
  --app-root TA-attack-coverage-advisor \
  --security-content /tmp/security_content
```

## Lookup Regeneration

```bash
python3 TA-attack-coverage-advisor/bin/attack_coverage_catalog_builder.py \
  --security-content /tmp/security_content \
  --output-dir TA-attack-coverage-advisor/lookups
```

To include experimental detections in the packaged catalog:

```bash
python3 TA-attack-coverage-advisor/bin/attack_coverage_catalog_builder.py \
  --security-content /tmp/security_content \
  --output-dir TA-attack-coverage-advisor/lookups \
  --include-experimental
```

## References

- French usage guide: [`GUIDE_UTILISATION_FR.md`](GUIDE_UTILISATION_FR.md)
- Splunk Security Content: https://github.com/splunk/security_content
- Security Content data sources: https://github.com/splunk/security_content/tree/develop/data_sources
- Splunk ES overview: https://help.splunk.com/en/splunk-enterprise-security-8/user-guide/8.5/introduction/about-splunk-enterprise-security
- Splunk ES detection annotations: https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.2/detections/add-annotations-to-detections-in-splunk-enterprise-security
- MITRE ATT&CK in Splunk Security Essentials: https://help.splunk.com/en/splunk-enterprise-security-8/security-essentials/use-splunk-security-essentials/3.8/use-the-analytics-advisor-in-splunk-security-essentials/the-mitre-attck-framework-dashboard
