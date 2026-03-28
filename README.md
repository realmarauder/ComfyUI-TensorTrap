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
- Suspicious input values (code-like patterns in text fields)

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

1. **Add nodes** from the "TensorTrap/Security" category in ComfyUI's node menu
2. **Scan Model** — Connect a file path string to the Scan Model node, then connect its output to your model loader
3. **Audit Nodes** — Add the Audit node anywhere and run the workflow to get a report of all installed node packages
4. **Analyze Workflow** — Add the Analyze node to check the current workflow for dangerous patterns

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
