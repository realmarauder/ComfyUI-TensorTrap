# ComfyUI-TensorTrap

Security scanner for ComfyUI. Scans model files before loading, audits installed custom nodes for dangerous code, and analyzes workflow graphs for threat patterns.

Powered by [TensorTrap](https://github.com/realmarauder/TensorTrap).

## Why This Exists

ComfyUI's custom node ecosystem has been the target of multiple real-world attacks:

- **Nullbulge** (2024) — Compromised LLMVISION extension stole browser passwords, credit cards, and crypto wallets
- **Ultralytics supply chain** (2024) — Cryptominer pushed through Impact-Pack dependency
- **Akira Stealer** (2026) — Fake upscaler nodes distributed infostealer malware
- **Pickai backdoor** (2025) — 695+ ComfyUI servers compromised with C++ backdoor

There are 8+ documented CVEs, 2,000+ unvetted custom nodes, and 2.5 million shared workflows. ComfyUI has no runtime sandboxing — every custom node runs with full system access.

**ComfyUI-TensorTrap is the first tool that analyzes workflow execution graphs for security threats**, not just individual files.

See the [full security research](https://github.com/realmarauder/TensorTrap/tree/main/research_projects) for details.

## Features

### Scan Model (TensorTrap)
Drop this node before any model loader. It scans the model file for:
- Malicious pickle opcodes (os.system, subprocess, eval, exec)
- Polyglot attacks (malware hidden in images/video)
- Archive bypass exploits (CVE-2025-1889, CVE-2025-1716)
- Obfuscation patterns (base64, hex encoding)

If threats are found, the node blocks the workflow from executing.

### Audit Installed Nodes (TensorTrap)
Scans all installed custom node packages for dangerous code patterns:
- `eval()`, `exec()`, `compile()` — code injection
- `subprocess`, `os.system` — command execution
- Network access (`requests`, `urllib`, `socket`) — data exfiltration
- `pickle.loads` — deserialization attacks
- Obfuscated code (PyArmor, base64-encoded payloads)
- Suspicious binary files (.exe, .dll, .so)

### Analyze Workflow (TensorTrap)
Analyzes the current workflow's node graph for:
- Known dangerous node types (CVE-2024-21576, CVE-2024-21577)
- Dangerous data flows (string outputs feeding into eval nodes)
- URL injection risks (external URLs in download nodes)
- Pickle-deserializer abuse (CWE-502) — e.g. `Base64ToConditioning` from RES4LYF with a literal payload, or a connection from a source outside the trusted-producer set
- Base64-encoded pickle payloads smuggled into generic string widgets
- Sensitive filesystem paths in widget values (`/etc/passwd`, `~/.ssh/id_rsa`, AWS/GitHub credential paths, deep `../` traversal)
- Suspicious code-shaped strings (`__reduce__`, `__class__.__bases__`, `__builtins__`, `pickle.loads`, `compile()`, etc.)

Set `block_on_threat=True` (the default) and the node raises and stops the queue when it sees a finding at or above `min_severity` (default `HIGH`). Set `block_on_threat=False` to get reports without blocking.

### Preflight Check (TensorTrap)
One-stop composite node that runs all three audits and blocks on any finding at or above `min_severity`. Wire it once at the top of your workflow and the whole graph is gated. Each section (model scan, node audit, workflow analysis) can be skipped independently. Optionally takes a `model_path` to scan a specific file as part of the check.

## Installation

### Via ComfyUI Manager (Recommended)
Search for "TensorTrap" in ComfyUI Manager and click Install.

### Manual Installation
```bash
cd ComfyUI/custom_nodes/
git clone https://github.com/realmarauder/ComfyUI-TensorTrap.git
pip install tensortrap
```

### Requirements
- ComfyUI
- Python 3.10+
- TensorTrap (`pip install tensortrap`)

## Usage

All four nodes live under the **TensorTrap/Security** category in ComfyUI's node menu. None of them touch your generation pipeline — they sit alongside it and report (or block).

### Quick start: three things you can do today

**1. Audit your installed nodes after every `git pull` or ComfyUI Manager install.**

Build a tiny side workflow: drop **Audit Installed Nodes**, connect its `audit_report` output to any Show Text / Display String node (from pysssss, rgthree, was-node-suite, etc.), and queue it. You'll get a per-package report of dangerous patterns (`eval`, `exec`, `subprocess`, `os.system`, `pickle.loads`, hardcoded URLs, obfuscated payloads). If a pack you trust shows up flagged, file an issue with the maintainer — this is exactly how [RES4LYF #252](https://github.com/ClownsharkBatwing/RES4LYF/issues/252) was filed and fixed.

```
[Audit Installed Nodes]  →  audit_report          →  [Show Text]
                            total_packages        →  (optional)
                            packages_with_issues  →  (optional)
```

**2. Analyze any workflow you didn't write before you run it.**

When you pull a workflow JSON from Civitai, Discord, or Reddit, open it in ComfyUI, drop in **Analyze Workflow**, and queue. The node reads the active workflow graph and flags:

- Known dangerous node types (CVE-2024-21576, CVE-2024-21577)
- Suspicious string flows (raw text feeding into eval-like nodes)
- Embedded URLs in download nodes
- Code-shaped values pasted into text fields

If anything fires, you see it before the malicious node code actually runs.

```
[Analyze Workflow]  →  analysis_report  →  [Show Text]
                       is_safe          →  (optional)
                       findings_count   →  (optional)
```

**3. Scan a specific model file before loading it.**

The **Scan Model** node takes a `STRING` path and returns three outputs: the same path (pass-through), a JSON scan report, and an `is_safe` boolean. Wire it like:

```
[Primitive: STRING "models/checkpoints/foo.safetensors"]
        │
        ▼
[Scan Model]  →  model_path   →  (your path-based loader, e.g. Load Diffusion Model)
                 scan_report  →  [Show Text]  (optional)
                 is_safe      →  (Conditional / Switch node, optional)
```

By default the node raises and stops the queue when it sees HIGH or CRITICAL findings. Lower `min_severity` to `MEDIUM` for paranoid mode; set `block_on_threat=False` if you just want the report without blocking.

For checkpoints loaded via `CheckpointLoaderSimple` (dropdown selector, not a path), skip this node and run the CLI: `tensortrap scan models/checkpoints/foo.safetensors`. Same engine, same findings.

### Recommended audit cadence

| When                                              | Run                                  |
|---------------------------------------------------|--------------------------------------|
| After installing or updating any custom node pack | **Audit Installed Nodes**            |
| Before running a workflow you didn't author       | **Analyze Workflow**                 |
| Before loading a model from an unfamiliar source  | **Scan Model** or `tensortrap scan`  |
| Before publishing a workflow you want to share    | All three (or **Preflight Check**)   |
| Default-on protection for any workflow            | **Preflight Check** at the top       |

Add the audit nodes once and leave them parked in a side group of your graph — they cost nothing when not queued.

### Tying into an existing RES4LYF / T5-offload workflow

If you use RES4LYF's `ConditioningToBase64` / `Base64ToConditioning` nodes (hardened in [PR #263](https://github.com/ClownsharkBatwing/RES4LYF/pull/263)), drop **Analyze Workflow** or **Preflight Check** into the same graph. Both nodes flag two specific RES4LYF-relevant patterns:

- **CRITICAL** — A `Base64ToConditioning` node has a literal non-empty `data` value in the workflow JSON itself. That is the exact CWE-502 attack pattern from [issue #252](https://github.com/ClownsharkBatwing/RES4LYF/issues/252): the payload runs through `pickle.loads()` the moment the workflow executes.
- **MEDIUM** — A `Base64ToConditioning` node has its `data` input wired to something other than a `ConditioningToBase64` node in the same graph. The flow may be legitimate, but verify it.

The pickle-deserializer registry that powers this check is a growing list — open an issue if you find another ComfyUI node that calls `pickle.loads()` on a workflow-supplied input and we will add it.

## Contributing

Contributions welcome! This project is part of the [TensorTrap](https://github.com/realmarauder/TensorTrap) security ecosystem.

### Contributors

- **[realmarauder](https://github.com/realmarauder)** (Sean Michael, M2 Dynamics) — Creator and maintainer
- **[JustMaier](https://github.com/JustMaier)** (Justin Maier, CivitAI) — Performance optimizations and CivitAI-scale testing that drove this initiative

### Research Collaboration

This project builds on active security research into AI workflow execution attacks. If you work on AI infrastructure security, we'd love to collaborate:

- [CivitAI](https://civitai.com) | [Hugging Face](https://huggingface.co) | [ComfyUI](https://github.com/comfyanonymous/ComfyUI) | [Replicate](https://replicate.com) | [RunPod](https://www.runpod.io) | [Stability AI](https://stability.ai) | [Vast.ai](https://vast.ai) | [Digital Ocean](https://www.digitalocean.com)

Contact: smichael.us@gmail.com | [M2 Dynamics](https://m2dynamics.us)

## License

MIT License

## About

ComfyUI-TensorTrap is developed by [M2 Dynamics](https://m2dynamics.us), specializing in AI/ML security consulting.
