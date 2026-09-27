# agentic-detection-mcp

An agentic detection-engineering workbench that lets an LLM drive Windows event-log analysis while the detection logic and security judgment stay human-owned.

At its core, this is an [MCP](https://modelcontextprotocol.io/) server that wraps the [Hayabusa](https://github.com/Yamato-Security/hayabusa) EVTX scanner so an LLM (via Claude Code or Claude Desktop) can run scans, filter findings by severity, and reason over structured results. The longer-term goal is a knowledge base of my own Sigma detection rules mapped to MITRE ATT&CK, with tooling to analyze detection coverage and surface gaps.

> **Status: in progress.** The tool layer (Module 3 below) is working. The detection-authoring and coverage-analysis layer is what I'm building next, and it's where the substance of the project lives. See [Roadmap](#roadmap).

## Origin and scope

The MCP server scaffolding follows a detection-engineering course that walks through wrapping Hayabusa as an MCP tool. That course material is the starting point, not the destination. I'm using it to stand up the plumbing, then building my own detection work on top:

- **Followed from the course:** the MCP server structure, the `scan_evtx` tool, the CLI-wrapper pattern.
- **My own work (in progress):** authored Sigma rules with documented detection logic, testing against real attack samples, ATT&CK coverage analysis, and the failure-mode/security review of the setup.

I'm keeping this distinction explicit because the point of the project is the detection engineering, not the tutorial scaffolding.

## What it does now

- Exposes a `scan_evtx` MCP tool that runs Hayabusa against an EVTX file and returns findings as structured JSON, filterable by minimum severity.
- Registers as a project-scoped MCP server (`.mcp.json`) so it's available inside Claude Code sessions.
- Includes a standalone test harness (`test_scan.py`) for exercising the tool outside the agent.

## Architecture

```
  Claude Code / Desktop  <--MCP-->  server.py  -->  Hayabusa CLI  -->  EVTX logs
```

The LLM decides *when* to invoke the tool and reasons over what comes back. The server handles input validation, building the CLI command, running the scan, and parsing output into structured results. The model does not generate detections or make security calls; it orchestrates tooling and surfaces results for a human to judge.

## Setup

Requirements: Python 3.10+ and Hayabusa.

```bash
# 1. Clone and enter the project
git clone https://github.com/Samyukta-14/agentic-detection-mcp.git
cd agentic-detection-mcp

# 2. Create a virtual environment and install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 3. Fetch Hayabusa (downloads the latest release for your platform)
./download-hayabusa.sh
```

### Registering the MCP server

The included `.mcp.json` uses absolute paths from my machine, so adjust the `command` and `cwd` to your own clone, or re-register with:

```bash
claude mcp add --scope project agentic-detection-mcp -- /absolute/path/to/.venv/bin/python server.py
```

Then launch Claude Code from the project directory, approve the server when prompted, and confirm with `/mcp`.

### Testing without the agent

```bash
.venv/bin/python test_scan.py
```

You'll need a sample EVTX file. The [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) repo (courtesy of Samir Bousseaden) is a good source.

## Roadmap

- [ ] Author original Sigma rules for a chosen set of ATT&CK techniques, with documented detection logic and false-positive reasoning
- [ ] Test detections against known attack samples and document what fired, what was missed, and why
- [ ] Expose Sigma rules and ATT&CK mappings as MCP resources (knowledge-base layer)
- [ ] Add a coverage-analysis tool that reports detected techniques vs. gaps for a given tactic
- [ ] Write up the security failure modes of the setup (prompt injection via tool output, command-injection / path-traversal surface, over-trust in model reasoning)

## Security note

This is defensive tooling: log analysis, detection rules, and coverage assessment. It builds on published open-source projects (Hayabusa, Sigma, MITRE ATT&CK). The wrapper shells out to a CLI, so input validation and command-construction safety are part of the design and are covered in the roadmap's failure-mode write-up.

## Acknowledgements

- [Hayabusa](https://github.com/Yamato-Security/hayabusa) by Yamato Security
- [Sigma](https://github.com/SigmaHQ/sigma) detection rule format
- [MITRE ATT&CK](https://attack.mitre.org/)
- [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) by Samir Bousseaden
