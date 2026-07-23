"""MCP server that wraps Hayabusa for EVTX (Windows Event Log) analysis.

Exposes two tools:
- `scan_evtx`: Runs the Hayabusa CLI against EVTX files, filters detections by
  severity, rule name, and other parameters, returning structured results.
- `get_hayabusa_rules`: Lists available Hayabusa rules with optional filtering
  by keyword and severity level, helping Claude understand what rules exist.
"""

from __future__ import annotations

import glob
import json
import os
import shutil
import subprocess
import tempfile
from collections import Counter
from pathlib import Path

import yaml

from mcp.server.fastmcp import FastMCP

# The server instance. The name is what MCP clients see.
mcp = FastMCP("agentic-detection-mcp")

# Severity ordering. Hayabusa emits either full names or abbreviations
# depending on the output profile, so both forms map to the same rank.
LEVEL_RANK = {
    "info": 0, "informational": 0,
    "low": 1,
    "med": 2, "medium": 2,
    "high": 3,
    "crit": 4, "critical": 4,
    "emer": 5, "emergency": 5,
}

# Values accepted for the `min_severity` parameter (matches Hayabusa's -m).
VALID_MIN_SEVERITY = ["informational", "low", "medium", "high", "critical"]

# How long to let a scan run before giving up (seconds).
SCAN_TIMEOUT = int(os.environ.get("HAYABUSA_TIMEOUT", "600"))


def _find_hayabusa() -> str | None:
    """Locate the Hayabusa binary.

    Order: $HAYABUSA_BIN, the bundled ./hayabusa/ directory, then $PATH.
    """
    env = os.environ.get("HAYABUSA_BIN")
    if env and Path(env).is_file():
        return env

    bundled = sorted(
        p for p in glob.glob(str(Path(__file__).parent / "hayabusa" / "hayabusa*"))
        if Path(p).is_file() and os.access(p, os.X_OK)
    )
    if bundled:
        return bundled[-1]  # highest version if several

    return shutil.which("hayabusa")


def _rules_args(binary: str) -> list[str]:
    """Return -r/-c args pointing at the rules bundled next to the binary.

    Hayabusa defaults to ./rules relative to the CWD; passing explicit paths
    lets the server run from any working directory.
    """
    base = Path(binary).parent
    rules = base / "rules"
    config = rules / "config"
    args: list[str] = []
    if rules.is_dir():
        args += ["-r", str(rules)]
    if config.is_dir():
        args += ["-c", str(config)]
    return args


def _level_rank(level: str) -> int:
    """Rank a Hayabusa level string; unknown levels sort lowest."""
    return LEVEL_RANK.get(str(level).strip().lower(), -1)


def _find_rules_directory() -> Path | None:
    """Locate the Hayabusa rules directory.

    Searches relative to the binary location, or in the current directory.
    """
    binary = _find_hayabusa()
    if binary:
        base = Path(binary).parent
        rules = base / "rules"
        if rules.is_dir():
            return rules

    local_rules = Path(__file__).parent / "hayabusa" / "rules"
    if local_rules.is_dir():
        return local_rules

    return None


def _parse_rule_file(file_path: Path) -> dict | None:
    """Parse a Hayabusa rule YAML file and extract metadata.

    Returns a dict with rule info, or None if parsing fails.
    """
    try:
        with open(file_path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if not isinstance(data, dict):
            return None

        return {
            "file": str(file_path.relative_to(file_path.parent.parent.parent)),
            "title": data.get("title", ""),
            "description": data.get("description", ""),
            "id": data.get("id", ""),
            "level": data.get("level", ""),
            "status": data.get("status", ""),
            "author": data.get("author", ""),
            "date": str(data.get("date", "")),
            "tags": data.get("tags", []),
            "references": data.get("references", []),
            "ruletype": data.get("ruletype", ""),
        }
    except (OSError, yaml.YAMLError):
        return None


@mcp.tool()
def scan_evtx(
    path: str,
    min_severity: str = "informational",
    rule_filter: str | None = None,
    output_format: str = "summary",
    max_results: int | None = None,
) -> dict:
    """Scan an EVTX file with Hayabusa and return detections as structured JSON.

    Args:
        path: Path to a single .evtx file, or a directory of .evtx files.
        min_severity: Minimum severity to include — one of
            "informational", "low", "medium", "high", "critical".
        rule_filter: Optional filter string; only include rules with titles
            containing this substring (case-insensitive).
        output_format: "summary" (default) returns aggregated counts and top results;
            "full" returns complete detection objects.
        max_results: Optional limit on number of detections to return.

    Returns:
        A dict with a ``status`` key. On success:
        ``{"status": "ok", "path", "min_severity", "count", "detections": [...]}``.
        On failure: ``{"status": "error", "error", "detail"}``.
    """
    # --- Validate inputs -----------------------------------------------------
    min_severity = min_severity.strip().lower()
    if min_severity not in VALID_MIN_SEVERITY:
        return {
            "status": "error",
            "error": "invalid_min_severity",
            "detail": f"min_severity must be one of {VALID_MIN_SEVERITY}, got {min_severity!r}.",
        }

    output_format = output_format.strip().lower()
    if output_format not in ("summary", "full"):
        return {
            "status": "error",
            "error": "invalid_output_format",
            "detail": f"output_format must be 'summary' or 'full', got {output_format!r}.",
        }

    if max_results is not None and max_results < 0:
        return {
            "status": "error",
            "error": "invalid_max_results",
            "detail": f"max_results must be non-negative, got {max_results}.",
        }

    rule_filter_lower = rule_filter.strip().lower() if rule_filter else None

    target = Path(path)
    if not target.exists():
        return {
            "status": "error",
            "error": "file_not_found",
            "detail": f"No such file or directory: {path}",
        }
    input_flag = "-d" if target.is_dir() else "-f"

    # --- Locate Hayabusa -----------------------------------------------------
    binary = _find_hayabusa()
    if binary is None:
        return {
            "status": "error",
            "error": "hayabusa_not_found",
            "detail": (
                "Hayabusa CLI not found. Run ./download-hayabusa.sh, set "
                "$HAYABUSA_BIN, or install hayabusa on your PATH."
            ),
        }

    # --- Run the scan --------------------------------------------------------
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
        out_path = tmp.name

    cmd = [
        binary, "json-timeline",
        input_flag, str(target),
        "-L",               # JSONL output
        "-o", out_path,
        "-m", min_severity,  # let Hayabusa skip lower-severity rules
        "-w",               # no interactive wizard
        "-q",               # no banner
        "-Q",               # do not write error logs
        "-C",               # clobber existing output file
        "-K",               # no color codes
        "-N",               # no results summary
        *_rules_args(binary),
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=SCAN_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        os.unlink(out_path)
        return {
            "status": "error",
            "error": "scan_timeout",
            "detail": f"Hayabusa scan exceeded {SCAN_TIMEOUT}s.",
        }
    except OSError as exc:
        os.unlink(out_path)
        return {"status": "error", "error": "scan_launch_failed", "detail": str(exc)}

    if proc.returncode != 0:
        os.unlink(out_path)
        return {
            "status": "error",
            "error": "scan_failed",
            "detail": (proc.stderr or proc.stdout or "").strip()
            or f"Hayabusa exited with code {proc.returncode}.",
        }

    # --- Parse & filter output ----------------------------------------------
    threshold = _level_rank(min_severity)
    detections: list[dict] = []
    try:
        with open(out_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue  # skip any non-record lines defensively
                level = record.get("Level", "")
                if _level_rank(level) < threshold:
                    continue
                if rule_filter_lower:
                    rule_title = record.get("RuleTitle", "").lower()
                    if rule_filter_lower not in rule_title:
                        continue
                detections.append(record)
    except OSError as exc:
        return {"status": "error", "error": "output_read_failed", "detail": str(exc)}
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass

    # --- Apply result limiting and formatting --------------------------------
    total_count = len(detections)
    if max_results is not None:
        detections = detections[:max_results]

    if output_format == "full":
        return {
            "status": "ok",
            "path": str(target),
            "min_severity": min_severity,
            "rule_filter": rule_filter,
            "count": len(detections),
            "total_matching": total_count,
            "detections": detections,
        }

    # --- Generate summary format ---------------------------------------------
    severity_counts = Counter(d.get("Level", "unknown") for d in detections)
    rule_counts = Counter(d.get("RuleTitle", "unknown") for d in detections)
    computer_counts = Counter(d.get("Computer", "unknown") for d in detections)

    return {
        "status": "ok",
        "path": str(target),
        "min_severity": min_severity,
        "rule_filter": rule_filter,
        "count": len(detections),
        "total_matching": total_count,
        "severity_breakdown": dict(severity_counts),
        "top_rules": dict(rule_counts.most_common(10)),
        "affected_computers": dict(computer_counts.most_common(10)),
        "sample_detections": detections[:5],
    }


@mcp.tool()
def get_hayabusa_rules(keyword: str | None = None, level_filter: str | None = None) -> dict:
    """List available Hayabusa rules, optionally filtered by keyword or severity level.

    This helps Claude understand what rules are available before running scans.

    Args:
        keyword: Optional keyword to filter rules by title, description, tags, or author
            (case-insensitive substring matching).
        level_filter: Optional severity level to filter by — one of
            "informational", "low", "medium", "high", "critical".

    Returns:
        A dict with a ``status`` key. On success:
        ``{"status": "ok", "count", "rules": [{...}, ...], "filters": {...}}``.
        On failure: ``{"status": "error", "error", "detail"}``.
    """
    rules_dir = _find_rules_directory()
    if rules_dir is None:
        return {
            "status": "error",
            "error": "rules_not_found",
            "detail": "Hayabusa rules directory not found.",
        }

    if level_filter is not None:
        level_filter = level_filter.strip().lower()
        if level_filter not in VALID_MIN_SEVERITY:
            return {
                "status": "error",
                "error": "invalid_level_filter",
                "detail": f"level_filter must be one of {VALID_MIN_SEVERITY}, got {level_filter!r}.",
            }

    keyword_lower = keyword.strip().lower() if keyword else None

    rules: list[dict] = []
    try:
        yaml_files = sorted(rules_dir.glob("**/*.yml"))
        for rule_file in yaml_files:
            rule = _parse_rule_file(rule_file)
            if rule is None:
                continue

            if level_filter and rule.get("level", "").lower() != level_filter:
                continue

            if keyword_lower:
                title = (rule.get("title") or "").lower()
                description = (rule.get("description") or "").lower()
                tags_list = rule.get("tags") or []
                tags = " ".join(str(t).lower() for t in tags_list)
                author = (rule.get("author") or "").lower()
                searchable = f"{title} {description} {tags} {author}"
                if keyword_lower not in searchable:
                    continue

            rules.append(rule)

    except OSError as exc:
        return {"status": "error", "error": "rules_read_failed", "detail": str(exc)}

    return {
        "status": "ok",
        "count": len(rules),
        "total_available": len(list(rules_dir.glob("**/*.yml"))),
        "filters": {
            "keyword": keyword,
            "level_filter": level_filter,
        },
        "rules": rules,
    }


def main() -> None:
    """Run the MCP server over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
