"""MCP server for detection engineering and EVTX analysis.

Exposes tools for event log scanning and rule inspection:
- `scan_evtx`: Runs the Hayabusa CLI against EVTX files, filters detections by
  severity, rule name, and other parameters, returning structured results.
- `get_hayabusa_rules`: Lists available Hayabusa rules with optional filtering
  by keyword and severity level.

Exposes resources for Sigma detection rules and ATT&CK coverage (detection:// URIs):
- `detection://rules`: List all available Sigma rules with metadata.
- `detection://rules/{rule_id}`: Get the full YAML content of a specific rule.
- `detection://rules/by-technique/{technique_id}`: Find all rules for an ATT&CK
  technique (e.g., T1566, T1486), enabling detection coverage queries.
- `detection://attack/techniques/{technique_id}`: Get ATT&CK technique details
  (name, description, platforms) with our detection rule coverage assessment
  (covered/partial/gap status).
"""

from __future__ import annotations

import glob
import json
import os
import shutil
import subprocess
import tempfile
import urllib.request
from collections import Counter
from pathlib import Path

import yaml

from mcp.server.fastmcp import FastMCP
from mcp.types import TextContent, Resource

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


def _find_sigma_rules_directory() -> Path | None:
    """Locate the Sigma rules directory.

    Looks for sigma-rules/ relative to this script.
    """
    local_sigma = Path(__file__).parent / "sigma-rules" / "rules"
    if local_sigma.is_dir():
        return local_sigma
    return None


def _parse_sigma_rule_file(file_path: Path) -> dict | None:
    """Parse a Sigma rule YAML file and extract metadata.

    Returns a dict with rule info, or None if parsing fails.
    """
    try:
        with open(file_path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if not isinstance(data, dict):
            return None

        tags = data.get("tags", [])
        attack_tags = [tag.replace("attack.", "") for tag in tags if str(tag).startswith("attack.")]

        return {
            "id": data.get("id", ""),
            "title": data.get("title", ""),
            "description": data.get("description", ""),
            "author": data.get("author", ""),
            "date": str(data.get("date", "")),
            "status": data.get("status", ""),
            "level": data.get("level", ""),
            "tags": tags,
            "attack_techniques": attack_tags,
            "logsource": data.get("logsource", {}),
            "references": data.get("references", []),
            "falsepositives": data.get("falsepositives", []),
        }
    except (OSError, yaml.YAMLError):
        return None


def _load_all_sigma_rules() -> dict[str, dict]:
    """Load all Sigma rules from the sigma-rules directory.

    Returns a mapping of rule ID to rule metadata.
    """
    sigma_dir = _find_sigma_rules_directory()
    if not sigma_dir:
        return {}

    rules = {}
    try:
        for rule_file in sigma_dir.glob("**/*.yml"):
            rule = _parse_sigma_rule_file(rule_file)
            if rule and rule.get("id"):
                rules[rule["id"]] = {**rule, "file_path": str(rule_file.relative_to(sigma_dir.parent))}
    except OSError:
        pass

    return rules


# Cache for ATT&CK data (loaded on first use)
_ATTACK_CACHE: dict | None = None
_ATTACK_TECHNIQUES_CACHE: dict[str, dict] | None = None


def _fetch_attack_data() -> dict | None:
    """Fetch ATT&CK Enterprise data from GitHub.

    Returns the STIX bundle object, or None on error.
    """
    global _ATTACK_CACHE
    if _ATTACK_CACHE is not None:
        return _ATTACK_CACHE

    url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            _ATTACK_CACHE = json.loads(response.read().decode("utf-8"))
        return _ATTACK_CACHE
    except Exception:
        return None


def _build_attack_techniques_map() -> dict[str, dict]:
    """Build a mapping from ATT&CK technique ID to technique details.

    Returns a dict like: {"T1234": {"name": "...", "description": "...", ...}, ...}
    """
    global _ATTACK_TECHNIQUES_CACHE
    if _ATTACK_TECHNIQUES_CACHE is not None:
        return _ATTACK_TECHNIQUES_CACHE

    _ATTACK_TECHNIQUES_CACHE = {}
    attack_data = _fetch_attack_data()
    if not attack_data:
        return _ATTACK_TECHNIQUES_CACHE

    for obj in attack_data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue

        ext_refs = obj.get("external_references", [])
        for ext_ref in ext_refs:
            if ext_ref.get("source_name") == "mitre-attack":
                tech_id = ext_ref.get("external_id")
                if tech_id:
                    _ATTACK_TECHNIQUES_CACHE[tech_id] = {
                        "id": tech_id,
                        "name": obj.get("name", ""),
                        "description": obj.get("description", ""),
                        "url": ext_ref.get("url", ""),
                        "x_mitre_platforms": obj.get("x_mitre_platforms", []),
                    }
                break

    return _ATTACK_TECHNIQUES_CACHE


def _normalize_technique_id(tech_id: str) -> str:
    """Normalize a technique ID for consistent matching.

    Examples: "T1566" -> "T1566", "t1566.001" -> "T1566.001"
    """
    return tech_id.upper()


def _assess_coverage(
    technique_id: str,
    detected_by_rules: list[dict]
) -> str:
    """Assess detection coverage for a technique.

    Returns one of: "covered" (3+ rules), "partial" (1-2 rules), "gap" (0 rules)
    """
    rule_count = len(detected_by_rules)
    if rule_count >= 3:
        return "covered"
    elif rule_count >= 1:
        return "partial"
    else:
        return "gap"


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


@mcp.resource("detection://rules")
def list_sigma_rules() -> TextContent:
    """List all available Sigma detection rules with metadata."""
    rules = _load_all_sigma_rules()
    if not rules:
        return TextContent(
            type="text",
            text=json.dumps({
                "status": "error",
                "error": "no_rules_found",
                "detail": "Sigma rules directory not found or is empty."
            })
        )

    summary = []
    for rule_id, rule in sorted(rules.items(), key=lambda x: x[1].get("title", "")):
        summary.append({
            "id": rule_id,
            "title": rule.get("title", ""),
            "level": rule.get("level", ""),
            "status": rule.get("status", ""),
            "author": rule.get("author", ""),
            "techniques": rule.get("attack_techniques", []),
        })

    return TextContent(
        type="text",
        text=json.dumps({
            "status": "ok",
            "count": len(rules),
            "rules": summary
        }, indent=2)
    )


@mcp.resource("detection://rules/{rule_id}")
def get_sigma_rule(rule_id: str) -> TextContent:
    """Get the full content of a specific Sigma rule by ID."""
    rules = _load_all_sigma_rules()
    rule = rules.get(rule_id)

    if not rule:
        return TextContent(
            type="text",
            text=json.dumps({
                "status": "error",
                "error": "rule_not_found",
                "detail": f"Rule with ID {rule_id} not found."
            })
        )

    sigma_dir = _find_sigma_rules_directory()
    if not sigma_dir:
        return TextContent(
            type="text",
            text=json.dumps({
                "status": "error",
                "error": "sigma_dir_not_found",
                "detail": "Sigma rules directory not found."
            })
        )

    rule_file = sigma_dir.parent / rule.get("file_path", "")
    try:
        with open(rule_file, encoding="utf-8") as fh:
            rule_content = fh.read()
    except OSError:
        rule_content = "(Unable to read rule file)"

    return TextContent(
        type="text",
        text=rule_content
    )


@mcp.resource("detection://rules/by-technique/{technique_id}")
def list_rules_by_technique(technique_id: str) -> TextContent:
    """List all Sigma rules that detect a specific ATT&CK technique."""
    rules = _load_all_sigma_rules()
    normalized_technique = technique_id.lower().replace("t", "").lstrip("0")

    matching_rules = []
    for rule_id, rule in sorted(rules.items(), key=lambda x: x[1].get("title", "")):
        techniques = rule.get("attack_techniques", [])
        for tech in techniques:
            if normalized_technique in tech.lower().replace("t", "").lstrip("0"):
                matching_rules.append({
                    "id": rule_id,
                    "title": rule.get("title", ""),
                    "level": rule.get("level", ""),
                    "status": rule.get("status", ""),
                    "author": rule.get("author", ""),
                    "techniques": techniques,
                })
                break

    return TextContent(
        type="text",
        text=json.dumps({
            "status": "ok",
            "technique": technique_id,
            "count": len(matching_rules),
            "rules": matching_rules
        }, indent=2)
    )


@mcp.resource("detection://attack/techniques/{technique_id}")
def get_attack_technique(technique_id: str) -> TextContent:
    """Get ATT&CK technique details with detection rule coverage assessment."""
    normalized_id = _normalize_technique_id(technique_id)
    techniques_map = _build_attack_techniques_map()

    technique = techniques_map.get(normalized_id)
    if not technique:
        return TextContent(
            type="text",
            text=json.dumps({
                "status": "error",
                "error": "technique_not_found",
                "detail": f"ATT&CK technique {technique_id} not found.",
                "tried_id": normalized_id,
            })
        )

    rules = _load_all_sigma_rules()
    normalized_search = normalized_id.lower()

    detected_by_rules = []
    for rule_id, rule in sorted(rules.items(), key=lambda x: x[1].get("title", "")):
        techniques = rule.get("attack_techniques", [])
        for tech in techniques:
            if normalized_search == tech.lower():
                detected_by_rules.append({
                    "id": rule_id,
                    "title": rule.get("title", ""),
                    "level": rule.get("level", ""),
                    "status": rule.get("status", ""),
                    "author": rule.get("author", ""),
                })
                break

    coverage = _assess_coverage(normalized_id, detected_by_rules)

    return TextContent(
        type="text",
        text=json.dumps({
            "status": "ok",
            "technique": {
                "id": technique["id"],
                "name": technique["name"],
                "description": technique["description"],
                "url": technique["url"],
                "platforms": technique.get("x_mitre_platforms", []),
            },
            "detection": {
                "coverage": coverage,
                "rule_count": len(detected_by_rules),
                "rules": detected_by_rules,
            },
            "coverage_notes": {
                "covered": "3 or more rules detect this technique",
                "partial": "1-2 rules detect this technique",
                "gap": "No detection rules available for this technique",
            }
        }, indent=2)
    )


def main() -> None:
    """Run the MCP server over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
