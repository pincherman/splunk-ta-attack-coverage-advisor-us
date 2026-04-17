#!/usr/bin/env python3
"""Local validation helper for TA-attack-coverage-advisor."""

from __future__ import annotations

import argparse
import csv
import py_compile
import subprocess
import sys
import tempfile
from pathlib import Path


REQUIRED_FILES = [
    "README.md",
    "default/app.conf",
    "default/commands.conf",
    "default/transforms.conf",
    "metadata/default.meta",
    "bin/attack_coverage_advisor.py",
    "bin/attack_coverage_catalog_builder.py",
    "lookups/attack_coverage_data_sources.csv",
    "lookups/attack_coverage_detections.csv",
    "lookups/attack_coverage_detection_data_sources.csv",
]

LOOKUP_FILES = [
    "attack_coverage_data_sources.csv",
    "attack_coverage_detections.csv",
    "attack_coverage_detection_data_sources.csv",
]


def count_csv_rows(path: Path) -> int:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return max(sum(1 for _ in csv.reader(handle)) - 1, 0)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--app-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Path to the TA root directory.",
    )
    parser.add_argument(
        "--security-content",
        default="/tmp/security_content",
        help="Path to the local security_content clone used to validate the catalog builder.",
    )
    args = parser.parse_args()

    app_root = Path(args.app_root).expanduser().resolve()
    errors: list[str] = []

    for relative_path in REQUIRED_FILES:
        candidate = app_root / relative_path
        if not candidate.exists():
            errors.append(f"Missing required file: {candidate}")

    python_files = [
        app_root / "bin/attack_coverage_advisor.py",
        app_root / "bin/attack_coverage_catalog_builder.py",
        app_root / "bin/validate_local.py",
    ]
    for python_file in python_files:
        if python_file.exists():
            try:
                py_compile.compile(str(python_file), doraise=True)
            except py_compile.PyCompileError as error:
                errors.append(f"Python compile failed for {python_file}: {error}")

    security_content = Path(args.security_content).expanduser().resolve()
    if security_content.exists():
        with tempfile.TemporaryDirectory(prefix="attack-coverage-validate-") as temp_dir:
            result = subprocess.run(
                [
                    sys.executable,
                    str(app_root / "bin/attack_coverage_catalog_builder.py"),
                    "--security-content",
                    str(security_content),
                    "--output-dir",
                    temp_dir,
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                errors.append(
                    "Catalog builder failed: "
                    + (result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}")
                )
            else:
                for filename in LOOKUP_FILES:
                    generated = Path(temp_dir) / filename
                    if not generated.exists():
                        errors.append(f"Builder did not produce {generated}")
                    elif count_csv_rows(generated) <= 0:
                        errors.append(f"Generated CSV is empty: {generated}")
    else:
        print(f"warning: security_content path not found, skipping regeneration check: {security_content}")

    for filename in LOOKUP_FILES:
        packaged = app_root / "lookups" / filename
        if packaged.exists() and count_csv_rows(packaged) <= 0:
            errors.append(f"Packaged CSV is empty: {packaged}")

    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1

    print("Validation OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
