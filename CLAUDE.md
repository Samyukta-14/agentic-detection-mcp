# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

An MCP (Model Context Protocol) server that wraps [Hayabusa](https://github.com/Yamato-Security/hayabusa) for Windows Event Log (EVTX) analysis. The server exposes Hayabusa's detection capabilities as MCP tools so an agent can scan EVTX files and reason over the results.

## Stack

- **Python** with the `mcp` library (Model Context Protocol server SDK)
- **Hayabusa CLI** — installed locally; invoked as a subprocess by the server

## Goals

**Event Log Scanning (Module 3):**
- Expose a `scan_evtx` tool that runs Hayabusa against EVTX files
- Return results as structured JSON (not raw CLI text)
- Support filtering by severity level (e.g. critical/high/medium/low)
- Handle errors gracefully (missing files, Hayabusa not installed, non-zero exit codes, malformed output)

**Detection Engineering Knowledge Base:**
- Expose Sigma rules as browsable MCP resources
- Expose ATT&CK technique mappings to detection rules
- Allow Claude to query detection coverage for specific techniques
- Combine knowledge base with Hayabusa scanning for comprehensive threat analysis

## Commands

```bash
# Install dependencies (Python 3.10+)
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Download Hayabusa CLI (if not already present)
./download-hayabusa.sh

# Run the MCP server (serves over stdio, blocks waiting for client)
.venv/bin/python server.py
# Or via the mcp CLI:
.venv/bin/mcp run server.py
# Or interactive inspection (UI):
.venv/bin/mcp dev server.py

# Test the scan_evtx tool directly
.venv/bin/python test_scan.py
```

## Architecture

**Entry point:** `server.py`
- Uses FastMCP (high-level MCP server API in mcp 1.28.1)
- Implements a single tool: `scan_evtx(path: str, min_severity: str) -> dict`
- Exposes MCP resources for Sigma rules and ATT&CK mappings

**scan_evtx tool:**
- Takes an EVTX file path or directory and a minimum severity level (`informational`, `low`, `medium`, `high`, `critical`)
- Validates inputs and locates the Hayabusa binary (bundled in `./hayabusa/`, or via `$HAYABUSA_BIN` env var, or on `$PATH`)
- Invokes `hayabusa json-timeline` with `-L` (JSONL output), severity filtering via `-m`, and no-wizard mode (`-w`)
- Parses the JSONL output, filters detections by the requested severity threshold, and returns structured JSON
- Handles errors gracefully: file not found, Hayabusa not installed, scan timeouts, JSON parse failures, invalid severity levels

**Hayabusa integration:**
- Downloaded and extracted to `./hayabusa/` by `download-hayabusa.sh`
- Binary discovery: looks in env var → bundled directory (highest version) → system PATH
- Automatically points Hayabusa to bundled rules (`rules/` and `rules/config/`) so it runs from any working directory
- Timeout: 600 seconds (configurable via `$HAYABUSA_TIMEOUT`)

**Testing:**
- `test_scan.py` calls `scan_evtx()` directly against 278 sample EVTX files (cloned from https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
- Tests single-file scans, directory scans, severity filtering, and error cases
