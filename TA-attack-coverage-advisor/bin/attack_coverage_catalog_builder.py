#!/usr/bin/env python3
"""Build embedded lookup CSVs from the Splunk security_content repository."""

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path
from typing import Dict, Iterable, List

import yaml


DATA_SOURCES_FILENAME = "attack_coverage_data_sources.csv"
DETECTIONS_FILENAME = "attack_coverage_detections.csv"
DETECTION_DATA_SOURCES_FILENAME = "attack_coverage_detection_data_sources.csv"


def normalize(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (value or "").lower()).strip()


def split_join(values: Iterable[str]) -> str:
    cleaned = [str(value).strip() for value in values if str(value).strip()]
    return "; ".join(cleaned)


def family_for_name(name: str) -> str:
    tokens = re.split(r"[\s:/_-]+", name or "")
    return tokens[0] if tokens and tokens[0] else "unknown"


def read_yaml(path: Path) -> Dict:
    with path.open("r", encoding="utf-8") as handle:
        payload = yaml.safe_load(handle) or {}
    if not isinstance(payload, dict):
        raise ValueError(f"Expected mapping in {path}")
    return payload


def build_data_source_rows(base_dir: Path) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for path in sorted((base_dir / "data_sources").glob("*.yml")):
        payload = read_yaml(path)
        supported_ta = payload.get("supported_TA") or []
        rows.append(
            {
                "data_source_name": payload.get("name", "").strip(),
                "normalized_data_source_name": normalize(payload.get("name", "")),
                "family": family_for_name(payload.get("name", "")),
                "source": str(payload.get("source", "")).strip(),
                "sourcetype": str(payload.get("sourcetype", "")).strip(),
                "mitre_components": split_join(payload.get("mitre_components") or []),
                "supported_ta_names": split_join(item.get("name", "") for item in supported_ta),
                "supported_ta_versions": split_join(item.get("version", "") for item in supported_ta),
                "supported_ta_urls": split_join(item.get("url", "") for item in supported_ta),
                "output_fields": split_join(payload.get("output_fields") or payload.get("fields") or []),
                "source_file": str(path.relative_to(base_dir)),
            }
        )
    return rows


def build_detection_rows(base_dir: Path, include_experimental: bool) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for path in sorted((base_dir / "detections").rglob("*.yml")):
        if "deprecated" in path.parts or "removed" in path.parts:
            continue
        payload = read_yaml(path)
        status = str(payload.get("status", "")).strip().lower()
        if status not in {"production", "experimental"}:
            continue
        if status == "experimental" and not include_experimental:
            continue

        data_sources = [str(item).strip() for item in (payload.get("data_source") or []) if str(item).strip()]
        tags = payload.get("tags") or {}
        mitre_attack_ids = [str(item).strip() for item in (tags.get("mitre_attack_id") or []) if str(item).strip()]
        rows.append(
            {
                "detection_id": str(payload.get("id", "")).strip(),
                "detection_name": str(payload.get("name", "")).strip(),
                "normalized_detection_name": normalize(payload.get("name", "")),
                "catalog_status": status,
                "detection_type": str(payload.get("type", "")).strip(),
                "family": family_for_name(data_sources[0] if data_sources else payload.get("name", "")),
                "security_domain": str(tags.get("security_domain", "")).strip(),
                "analytic_story": split_join(tags.get("analytic_story") or []),
                "mitre_attack_ids": split_join(mitre_attack_ids),
                "technique_count": str(len(set(mitre_attack_ids))),
                "data_source_names": split_join(data_sources),
                "required_data_source_count": str(len(data_sources)),
                "products": split_join(tags.get("product") or []),
                "search": " ".join(str(payload.get("search", "")).split()),
                "how_to_implement": " ".join(str(payload.get("how_to_implement", "")).split()),
                "source_file": str(path.relative_to(base_dir)),
            }
        )
    return rows


def build_detection_data_source_rows(detections: Iterable[Dict[str, str]]) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for detection in detections:
        names = [name.strip() for name in detection["data_source_names"].split(";") if name.strip()]
        for data_source_name in names:
            row = dict(detection)
            row["data_source_name"] = data_source_name
            row["normalized_data_source_name"] = normalize(data_source_name)
            rows.append(row)
    return rows


def write_csv(path: Path, rows: List[Dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(rows[0].keys()) if rows else []
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--security-content",
        default="/tmp/security_content",
        help="Path to the local security_content repository clone.",
    )
    parser.add_argument(
        "--output-dir",
        default=str(Path(__file__).resolve().parents[1] / "lookups"),
        help="Directory where CSV lookups should be written.",
    )
    parser.add_argument(
        "--include-experimental",
        action="store_true",
        help="Include experimental detections in the generated catalog.",
    )
    args = parser.parse_args()

    base_dir = Path(args.security_content).expanduser().resolve()
    output_dir = Path(args.output_dir).expanduser().resolve()
    if not base_dir.exists():
        raise SystemExit(f"security_content path does not exist: {base_dir}")

    data_sources = build_data_source_rows(base_dir)
    detections = build_detection_rows(base_dir, include_experimental=args.include_experimental)
    detection_data_sources = build_detection_data_source_rows(detections)

    if not data_sources or not detections:
        raise SystemExit("Generated catalog is empty. Check the source repository path.")

    write_csv(output_dir / DATA_SOURCES_FILENAME, data_sources)
    write_csv(output_dir / DETECTIONS_FILENAME, detections)
    write_csv(output_dir / DETECTION_DATA_SOURCES_FILENAME, detection_data_sources)

    print(
        f"Generated {len(data_sources)} data sources, "
        f"{len(detections)} detections, "
        f"{len(detection_data_sources)} detection-data-source mappings into {output_dir}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
