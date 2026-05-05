#!/usr/bin/env python3
"""Render an InSpec/SAF scan summary as a Markdown table for GitHub Actions.

Reads the JSON produced by `saf view summary -j` on stdin and prints a
table to stdout suitable for $GITHUB_STEP_SUMMARY.

Expected input shape (first element of a list):
    {
      "profileName": "...",
      "compliance": <int>,
      "passed":    {"critical": N, "high": N, "medium": N, "low": N, "total": N},
      "failed":    {"critical": N, "high": N, "medium": N, "low": N, "total": N},
      "skipped":   {"critical": N, "high": N, "medium": N, "low": N, "total": N},
      "error":     {"critical": N, "high": N, "medium": N, "low": N, "total": N},
      "no_impact": {"none": N, "total": N}
    }
"""

import json
import sys

ROW_LABELS = ["Total", "Critical", "High", "Medium", "Low", "Not Applicable"]
COLUMN_HEADERS = [
    "Passed :white_check_mark:",
    "Failed :x:",
    "Not Reviewed :leftwards_arrow_with_hook:",
    "Not Applicable :heavy_minus_sign:",
    "Error :warning:",
]


def row_values(severity, data):
    """Return the five-column row values for the given severity label."""
    if severity == "Total":
        return [
            str(data["passed"]["total"]),
            str(data["failed"]["total"]),
            str(data["skipped"]["total"]),
            str(data["no_impact"]["total"]),
            str(data["error"]["total"]),
        ]
    if severity == "Not Applicable":
        return ["-", "-", "-", str(data["no_impact"]["total"]), "-"]
    key = severity.lower()
    return [
        str(data["passed"][key]),
        str(data["failed"][key]),
        str(data["skipped"][key]),
        "-",
        str(data["error"][key]),
    ]


def main():
    payload = json.load(sys.stdin)
    data = payload[0] if isinstance(payload, list) else payload

    width = max(len(label) for label in ROW_LABELS + COLUMN_HEADERS)
    pad = lambda s: s.ljust(width)

    header_left = f"Compliance: {data['compliance']}% :test_tube:"
    print(
        "| "
        + header_left
        + " | "
        + " | ".join(pad(col) for col in COLUMN_HEADERS)
        + " |"
    )
    print(
        "| "
        + "-" * width
        + " | "
        + " | ".join("-" * width for _ in COLUMN_HEADERS)
        + " |"
    )
    for row in ROW_LABELS:
        cells = row_values(row, data)
        print(
            "| "
            + pad(f"**{row}**")
            + " | "
            + " | ".join(pad(cell) for cell in cells)
            + " |"
        )


if __name__ == "__main__":
    main()
