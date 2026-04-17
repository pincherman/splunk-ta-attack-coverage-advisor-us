#!/usr/bin/env python3
"""Generating command for ATT&CK coverage analysis based on bundled lookups."""

from __future__ import annotations

import csv
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

APP_ROOT = Path(__file__).resolve().parents[1]
LIB_DIR = APP_ROOT / "bin" / "lib"
if str(LIB_DIR) not in sys.path:
    sys.path.insert(0, str(LIB_DIR))

from splunklib.results import JSONResultsReader
from splunklib.searchcommands import Configuration, GeneratingCommand, Option, dispatch
from splunklib.searchcommands.validators import Boolean, Integer


LOOKUPS_DIR = APP_ROOT / "lookups"
DATA_SOURCES_LOOKUP = LOOKUPS_DIR / "attack_coverage_data_sources.csv"
DETECTIONS_LOOKUP = LOOKUPS_DIR / "attack_coverage_detections.csv"



def normalize(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (value or "").lower()).strip()


def split_multivalue(value: str) -> List[str]:
    return [item.strip() for item in (value or "").split(";") if item.strip()]


def safe_int(value: str) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def clamp_ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round(float(numerator) / float(denominator), 3)


def load_csv(path: Path) -> List[Dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def extract_mitre_attack_ids(raw_annotations: str) -> List[str]:
    if not raw_annotations:
        return []
    try:
        payload = json.loads(raw_annotations)
    except Exception:
        return []

    found: List[str] = []

    def walk(value, key_hint: str = "") -> None:
        if isinstance(value, dict):
            for key, inner in value.items():
                walk(inner, str(key).lower())
            return
        if isinstance(value, list):
            for inner in value:
                walk(inner, key_hint)
            return
        if not isinstance(value, str):
            return
        if "mitre" not in key_hint and not re.search(r"T\d{4}(?:\.\d{3})?", value, flags=re.IGNORECASE):
            return
        for technique_id in re.findall(r"T\d{4}(?:\.\d{3})?", value.upper()):
            if technique_id not in found:
                found.append(technique_id)

    walk(payload)
    return found


@Configuration(type="events")
class AttackCoverageAdvisorCommand(GeneratingCommand):
    mode = Option(require=False, default="full")
    earliest = Option(require=False, default="-30d")
    latest = Option(require=False, default="now")
    index = Option(require=False, default="*")
    limit = Option(require=False, default=25, validate=Integer(1))
    include_partial = Option(require=False, default=True, validate=Boolean())
    include_experimental = Option(require=False, default=False, validate=Boolean())

    def generate(self):
        mode = (self.mode or "full").strip().lower()
        valid_modes = {"summary", "inventory", "current", "potential", "gaps", "full"}
        if mode not in valid_modes:
            raise ValueError(f"Unsupported mode={mode!r}. Expected one of {sorted(valid_modes)}")
        if self.service is None:
            raise RuntimeError("Splunk service context unavailable. Verify commands.conf requires_srinfo=true.")

        data_sources = load_csv(DATA_SOURCES_LOOKUP)
        detections = load_csv(DETECTIONS_LOOKUP)
        if not self.include_experimental:
            detections = [row for row in detections if row.get("catalog_status") != "experimental"]

        detections_by_name = self._index_detections_by_name(detections)
        detections_by_source = self._index_detections_by_source(detections)

        inventory_rows, present_data_sources = self._build_inventory_rows(data_sources)
        es_installed, es_reason = self._detect_es()
        active_rows, active_names = self._build_current_rows(detections_by_name, es_installed, es_reason)
        potential_rows, detection_state = self._build_potential_rows(detections, active_names, present_data_sources, es_installed)
        gap_rows = self._build_gap_rows(
            data_sources=data_sources,
            detections_by_source=detections_by_source,
            active_names=active_names,
            detection_state=detection_state,
            present_data_sources=present_data_sources,
        )
        summary_rows = self._build_summary_rows(
            es_installed=es_installed,
            es_reason=es_reason,
            present_data_sources=present_data_sources,
            inventory_rows=inventory_rows,
            active_rows=active_rows,
            potential_rows=potential_rows,
            gap_rows=gap_rows,
        )

        sections = {
            "summary": summary_rows,
            "inventory": self._limit_rows(self._sort_inventory_rows(inventory_rows)),
            "current": self._limit_rows(self._sort_current_rows(active_rows)),
            "potential": self._limit_rows(self._sort_potential_rows(potential_rows)),
            "gaps": self._limit_rows(self._sort_gap_rows(gap_rows)),
        }

        if mode == "full":
            ordered_sections = ["summary", "inventory", "current", "potential", "gaps"]
        elif mode == "summary":
            ordered_sections = ["summary"]
        else:
            ordered_sections = [mode]

        for section_name in ordered_sections:
            for row in sections[section_name]:
                yield row

    def _base_row(self) -> Dict[str, object]:
        return {
            "section": "",
            "status": "",
            "family": "",
            "data_source_name": "",
            "detection_name": "",
            "mitre_attack_ids": "",
            "technique_count": 0,
            "reason": "",
            "recommendation": "",
            "scenario": "",
            "es_installed": "",
            "matched_data_source_count": 0,
            "required_data_source_count": 0,
            "match_ratio": 0.0,
            "detection_count": 0,
            "supported_ta_names": "",
            "supported_ta_versions": "",
            "catalog_status": "",
            "inventory_match": "",
            "search_window": f"{self.earliest} to {self.latest}",
        }

    def _index_detections_by_name(self, detections: Sequence[Dict[str, str]]) -> Dict[str, Dict[str, str]]:
        indexed: Dict[str, Dict[str, str]] = {}
        for row in sorted(detections, key=lambda item: (item.get("catalog_status") != "production", item.get("detection_name", ""))):
            indexed.setdefault(row["normalized_detection_name"], row)
        return indexed

    def _index_detections_by_source(self, detections: Sequence[Dict[str, str]]) -> Dict[str, List[Dict[str, str]]]:
        indexed: Dict[str, List[Dict[str, str]]] = defaultdict(list)
        for detection in detections:
            for name in split_multivalue(detection.get("data_source_names", "")):
                indexed[name].append(detection)
        return indexed

    def _run_oneshot(self, search: str) -> List[Dict[str, str]]:
        oneshot_kwargs = {"output_mode": "json"}
        if not search.lstrip().startswith("| rest"):
            oneshot_kwargs.update({"earliest_time": self.earliest, "latest_time": self.latest})
        reader = JSONResultsReader(self.service.jobs.oneshot(search, **oneshot_kwargs))
        rows: List[Dict[str, str]] = []
        for item in reader:
            if isinstance(item, dict):
                rows.append({str(key): "" if value is None else str(value) for key, value in item.items()})
        return rows

    def _metadata_inventory(self, metadata_type: str) -> Dict[str, Dict[str, str]]:
        values: Dict[str, Dict[str, str]] = {}
        indexes = [item.strip() for item in self.index.split(",") if item.strip()] or ["*"]
        field_name = "sourcetype" if metadata_type == "sourcetypes" else "source"
        for index_name in indexes:
            search = f"| metadata type={metadata_type} index={index_name}"
            for row in self._run_oneshot(search):
                key = row.get(field_name, "").strip()
                if not key:
                    continue
                existing = values.get(key, {})
                total_count = safe_int(existing.get("totalCount")) + safe_int(row.get("totalCount"))
                recent_time = max(existing.get("recentTime", ""), row.get("recentTime", ""), row.get("lastTime", ""))
                values[key] = {"totalCount": str(total_count), "recentTime": recent_time}
        return values

    def _build_inventory_rows(self, data_sources: Sequence[Dict[str, str]]) -> Tuple[List[Dict[str, object]], Dict[str, Dict[str, object]]]:
        sourcetypes = self._metadata_inventory("sourcetypes")
        sources = self._metadata_inventory("sources")

        present: Dict[str, Dict[str, object]] = {}
        rows: List[Dict[str, object]] = []
        for row in data_sources:
            matches: List[str] = []
            sourcetype = row.get("sourcetype", "").strip()
            source = row.get("source", "").strip()
            if sourcetype and sourcetype in sourcetypes:
                matches.append(f"sourcetype={sourcetype}")
            if source and source in sources:
                matches.append(f"source={source}")
            if not matches:
                continue

            present[row["data_source_name"]] = {
                "family": row.get("family", ""),
                "supported_ta_names": row.get("supported_ta_names", ""),
                "supported_ta_versions": row.get("supported_ta_versions", ""),
                "inventory_match": "; ".join(matches),
                "source": source,
                "sourcetype": sourcetype,
            }
            base = self._base_row()
            base.update(
                {
                    "section": "inventory",
                    "status": "present",
                    "family": row.get("family", ""),
                    "data_source_name": row.get("data_source_name", ""),
                    "reason": f"Telemetry observed in indexed data via {' and '.join(matches)}.",
                    "recommendation": "Telemetry is available. Use it to validate or activate mapped detections.",
                    "scenario": "inventory",
                    "inventory_match": "; ".join(matches),
                    "supported_ta_names": row.get("supported_ta_names", ""),
                    "supported_ta_versions": row.get("supported_ta_versions", ""),
                }
            )
            rows.append(base)
        return rows, present

    def _detect_es(self) -> Tuple[bool, str]:
        search = "| rest /services/apps/local splunk_server=local count=5000 | search name=SplunkEnterpriseSecuritySuite disabled=0 | fields name version label"
        try:
            rows = self._run_oneshot(search)
        except Exception as error:  # pragma: no cover - exercised in Splunk runtime
            return False, f"Unable to query installed apps via REST ({error}). Running in degraded what-if mode."
        if rows:
            version = rows[0].get("version", "unknown")
            return True, f"Enterprise Security detected on this search head (version {version})."
        return False, "Enterprise Security app not detected; running in degraded what-if mode."

    def _build_current_rows(
        self,
        detections_by_name: Dict[str, Dict[str, str]],
        es_installed: bool,
        es_reason: str,
    ) -> Tuple[List[Dict[str, object]], set]:
        if not es_installed:
            summary = self._base_row()
            summary.update(
                {
                    "section": "current",
                    "status": "unavailable",
                    "reason": es_reason,
                    "recommendation": "Current mode requires Enterprise Security with enabled correlation searches.",
                    "scenario": "no_es",
                    "es_installed": "false",
                }
            )
            return [summary], set()

        search = (
            "| rest /servicesNS/-/-/saved/searches splunk_server=local count=5000 "
            '| search action.correlationsearch.enabled=1 disabled=0 '
            '| fields title eai:acl.app action.correlationsearch.annotations'
        )
        try:
            rows = self._run_oneshot(search)
        except Exception as error:  # pragma: no cover - exercised in Splunk runtime
            failure = self._base_row()
            failure.update(
                {
                    "section": "current",
                    "status": "error",
                    "reason": f"Unable to query enabled correlation searches via REST: {error}",
                    "recommendation": "Validate user capabilities for /servicesNS/-/-/saved/searches or run degraded potential/gaps modes.",
                    "scenario": "es_installed",
                    "es_installed": "true",
                }
            )
            return [failure], set()
        results: List[Dict[str, object]] = []
        active_names = set()
        for row in rows:
            detection_name = row.get("title", "").strip()
            normalized_name = normalize(detection_name)
            if not normalized_name:
                continue
            active_names.add(normalized_name)
            catalog = detections_by_name.get(normalized_name)
            live_mitre_ids = extract_mitre_attack_ids(row.get("action.correlationsearch.annotations", ""))
            live_mitre_value = "; ".join(live_mitre_ids)
            base = self._base_row()
            if catalog:
                mitre_value = live_mitre_value or catalog.get("mitre_attack_ids", "")
                base.update(
                    {
                        "section": "current",
                        "status": "active",
                        "family": catalog.get("security_domain") or catalog.get("family", ""),
                        "data_source_name": catalog.get("data_source_names", ""),
                        "detection_name": detection_name,
                        "mitre_attack_ids": mitre_value,
                        "technique_count": len(split_multivalue(mitre_value)) if mitre_value else safe_int(catalog.get("technique_count")),
                        "reason": "Enabled ES correlation search mapped to the bundled security_content catalog and enriched from live annotations when available.",
                        "recommendation": "Keep enabled, validate tuning quality, and review adjacent inactive content in potential mode.",
                        "scenario": "es_installed",
                        "es_installed": "true",
                        "matched_data_source_count": safe_int(catalog.get("required_data_source_count")),
                        "required_data_source_count": safe_int(catalog.get("required_data_source_count")),
                        "match_ratio": 1.0,
                        "catalog_status": catalog.get("catalog_status", ""),
                    }
                )
            else:
                base.update(
                    {
                        "section": "current",
                        "status": "active_unmapped",
                        "family": row.get("eai:acl.app", ""),
                        "detection_name": detection_name,
                        "mitre_attack_ids": live_mitre_value,
                        "technique_count": len(live_mitre_ids),
                        "reason": "Enabled ES correlation search not found in the bundled security_content snapshot, but live annotations were used when present.",
                        "recommendation": "Review naming or custom content lineage if you want it reflected in this catalog-based report.",
                        "scenario": "es_installed",
                        "es_installed": "true",
                    }
                )
            results.append(base)
        if not results:
            summary = self._base_row()
            summary.update(
                {
                    "section": "current",
                    "status": "empty",
                    "reason": es_reason if es_installed else "Enterprise Security is not installed.",
                    "recommendation": "No enabled correlation searches were discovered.",
                    "scenario": "es_installed" if es_installed else "no_es",
                    "es_installed": "true" if es_installed else "false",
                }
            )
            results.append(summary)
        return results, active_names

    def _detection_match_state(
        self,
        detection: Dict[str, str],
        present_data_sources: Dict[str, Dict[str, object]],
    ) -> Dict[str, object]:
        required_sources = split_multivalue(detection.get("data_source_names", ""))
        matched_sources = [name for name in required_sources if name in present_data_sources]
        missing_sources = [name for name in required_sources if name not in present_data_sources]
        return {
            "required_sources": required_sources,
            "matched_sources": matched_sources,
            "missing_sources": missing_sources,
            "required_count": len(required_sources),
            "matched_count": len(matched_sources),
            "match_ratio": clamp_ratio(len(matched_sources), len(required_sources)),
        }

    def _build_potential_rows(
        self,
        detections: Sequence[Dict[str, str]],
        active_names: set,
        present_data_sources: Dict[str, Dict[str, object]],
        es_installed: bool,
    ) -> Tuple[List[Dict[str, object]], Dict[str, Dict[str, object]]]:
        results: List[Dict[str, object]] = []
        detection_state: Dict[str, Dict[str, object]] = {}

        for detection in detections:
            normalized_name = detection.get("normalized_detection_name", "")
            match_state = self._detection_match_state(detection, present_data_sources)
            detection_state[normalized_name] = match_state
            if es_installed and normalized_name in active_names:
                continue

            matched_count = match_state["matched_count"]
            required_count = match_state["required_count"]
            if matched_count <= 0:
                continue
            if matched_count < required_count and not self.include_partial:
                continue

            status = "activable" if matched_count == required_count else "partial"
            reason = (
                "All mapped data sources are present, but the detection is not enabled in ES."
                if es_installed and status == "activable"
                else "All mapped data sources are present; this detection becomes activable if ES content is adopted."
                if not es_installed and status == "activable"
                else f"{matched_count}/{required_count} mapped data sources are present. Additional telemetry may still be required."
            )
            recommendation = (
                "Review content dependencies, tune, and enable the detection."
                if status == "activable"
                else "Validate companion data sources, CIM alignment, and TA prerequisites before activation."
            )

            base = self._base_row()
            base.update(
                {
                    "section": "potential",
                    "status": status,
                    "family": detection.get("security_domain") or detection.get("family", ""),
                    "data_source_name": "; ".join(match_state["matched_sources"]),
                    "detection_name": detection.get("detection_name", ""),
                    "mitre_attack_ids": detection.get("mitre_attack_ids", ""),
                    "technique_count": safe_int(detection.get("technique_count")),
                    "reason": reason,
                    "recommendation": recommendation,
                    "scenario": "es_installed" if es_installed else "no_es",
                    "es_installed": "true" if es_installed else "false",
                    "matched_data_source_count": matched_count,
                    "required_data_source_count": required_count,
                    "match_ratio": match_state["match_ratio"],
                    "catalog_status": detection.get("catalog_status", ""),
                }
            )
            results.append(base)

        return results, detection_state

    def _build_gap_rows(
        self,
        data_sources: Sequence[Dict[str, str]],
        detections_by_source: Dict[str, List[Dict[str, str]]],
        active_names: set,
        detection_state: Dict[str, Dict[str, object]],
        present_data_sources: Dict[str, Dict[str, object]],
    ) -> List[Dict[str, object]]:
        rows: List[Dict[str, object]] = []

        for data_source in data_sources:
            name = data_source.get("data_source_name", "")
            if not name or name in present_data_sources:
                continue

            associated = detections_by_source.get(name, [])
            if not associated:
                continue

            technique_ids = set()
            detection_names = []
            immediate_ready_count = 0
            adjacent_count = 0
            useful_detection_count = 0

            for detection in associated:
                normalized_name = detection.get("normalized_detection_name", "")
                if normalized_name in active_names:
                    continue

                state = detection_state.get(normalized_name)
                if state is None:
                    state = self._detection_match_state(detection, present_data_sources)
                    detection_state[normalized_name] = state
                missing_sources = state["missing_sources"]
                matched_count = state["matched_count"]
                if not missing_sources or name not in missing_sources:
                    continue

                useful_detection_count += 1
                technique_ids.update(split_multivalue(detection.get("mitre_attack_ids", "")))
                detection_names.append(detection.get("detection_name", ""))
                if len(missing_sources) == 1:
                    immediate_ready_count += 1
                elif matched_count > 0:
                    adjacent_count += 1

            if useful_detection_count == 0:
                continue

            exemplar_detections = "; ".join(sorted(detection_names)[:3])
            recommendation = (
                f"Onboard {data_source.get('supported_ta_names')} {data_source.get('supported_ta_versions')} and validate CIM mapping."
                if data_source.get("supported_ta_names")
                else "Onboard this telemetry source and validate normalization before activating related detections."
            )
            base = self._base_row()
            base.update(
                {
                    "section": "gaps",
                    "status": "strategic_gap",
                    "family": data_source.get("family", ""),
                    "data_source_name": name,
                    "detection_name": exemplar_detections,
                    "mitre_attack_ids": "; ".join(sorted(technique_ids)),
                    "technique_count": len(technique_ids),
                    "reason": (
                        f"Missing telemetry source. It would fully ready {immediate_ready_count} detections immediately "
                        f"and contribute to {adjacent_count} more detections that still need companion sources."
                    ),
                    "recommendation": recommendation,
                    "scenario": "gap_analysis",
                    "supported_ta_names": data_source.get("supported_ta_names", ""),
                    "supported_ta_versions": data_source.get("supported_ta_versions", ""),
                    "detection_count": useful_detection_count,
                }
            )
            rows.append(base)

        return rows

    def _build_summary_rows(
        self,
        es_installed: bool,
        es_reason: str,
        present_data_sources: Dict[str, Dict[str, object]],
        inventory_rows: Sequence[Dict[str, object]],
        active_rows: Sequence[Dict[str, object]],
        potential_rows: Sequence[Dict[str, object]],
        gap_rows: Sequence[Dict[str, object]],
    ) -> List[Dict[str, object]]:
        active_techniques = self._unique_technique_count(active_rows)
        potential_techniques = self._unique_technique_count(potential_rows)
        gap_techniques = self._unique_technique_count(gap_rows)
        activable_count = sum(1 for row in potential_rows if row.get("status") == "activable")
        partial_count = sum(1 for row in potential_rows if row.get("status") == "partial")

        summary_specs = [
            (
                "inventory",
                "Inventory snapshot",
                len(inventory_rows),
                f"{len(present_data_sources)} mapped data sources were observed in indexed telemetry.",
                "Use mode=inventory to inspect each mapped source and the matching sourcetype/source evidence.",
            ),
            (
                "current" if es_installed else "current_unavailable",
                "Current ATT&CK coverage",
                active_techniques,
                es_reason if not es_installed else f"{len([row for row in active_rows if row.get('status') == 'active'])} enabled ES detections map to {active_techniques} ATT&CK techniques.",
                "Use mode=current to review the active enabled catalog view.",
            ),
            (
                "potential",
                "Potential ATT&CK unlock",
                potential_techniques,
                f"{activable_count} detections are immediately activable and {partial_count} are adjacent candidates with current telemetry.",
                "Use mode=potential to review which detections should be enabled or considered for ES adoption.",
            ),
            (
                "gaps",
                "Strategic telemetry gaps",
                gap_techniques,
                f"{len(gap_rows)} missing data sources map to projected ATT&CK expansion opportunities.",
                "Use mode=gaps to prioritize telemetry onboarding and TA deployment.",
            ),
        ]

        rows: List[Dict[str, object]] = []
        for status, detection_name, technique_count, reason, recommendation in summary_specs:
            base = self._base_row()
            base.update(
                {
                    "section": "summary",
                    "status": status,
                    "detection_name": detection_name,
                    "technique_count": technique_count,
                    "reason": reason,
                    "recommendation": recommendation,
                    "scenario": "es_installed" if es_installed else "no_es",
                    "es_installed": "true" if es_installed else "false",
                }
            )
            rows.append(base)
        return rows

    def _unique_technique_count(self, rows: Sequence[Dict[str, object]]) -> int:
        techniques = set()
        for row in rows:
            techniques.update(split_multivalue(str(row.get("mitre_attack_ids", ""))))
        return len(techniques)

    def _sort_inventory_rows(self, rows: Sequence[Dict[str, object]]) -> List[Dict[str, object]]:
        return sorted(rows, key=lambda row: (str(row.get("family", "")), str(row.get("data_source_name", ""))))

    def _sort_current_rows(self, rows: Sequence[Dict[str, object]]) -> List[Dict[str, object]]:
        return sorted(rows, key=lambda row: (-safe_int(row.get("technique_count")), str(row.get("detection_name", ""))))

    def _sort_potential_rows(self, rows: Sequence[Dict[str, object]]) -> List[Dict[str, object]]:
        status_rank = {"activable": 0, "partial": 1}
        return sorted(
            rows,
            key=lambda row: (
                status_rank.get(str(row.get("status", "")), 9),
                -safe_int(row.get("technique_count")),
                -safe_int(row.get("matched_data_source_count")),
                str(row.get("detection_name", "")),
            ),
        )

    def _sort_gap_rows(self, rows: Sequence[Dict[str, object]]) -> List[Dict[str, object]]:
        return sorted(
            rows,
            key=lambda row: (
                -safe_int(row.get("technique_count")),
                -safe_int(row.get("detection_count")),
                str(row.get("data_source_name", "")),
            ),
        )

    def _limit_rows(self, rows: Sequence[Dict[str, object]]) -> List[Dict[str, object]]:
        return list(rows[: int(self.limit)])


dispatch(AttackCoverageAdvisorCommand, module_name=__name__)
