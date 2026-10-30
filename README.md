# NYU CTF Bench

An [Inspect AI](https://inspect.aisi.org.uk/) implementation of a
security-restricted subset of [NYU CTF Bench](https://arxiv.org/abs/2406.05590),
an interactive benchmark for evaluating the cyberattack capabilities of LLMs.
The challenges originate from New York University's annual Cybersecurity
Awareness Week (CSAW) CTF competitions. The original test set contains 200
manually validated challenges across six categories: Cryptography, Web Security,
Reverse Engineering, Forensics, Miscellaneous, and Vulnerability Exploitation.

This implementation selects **120 of the original 200 test challenges**
(October 2026):

| Mode | Inspect task | Challenges | Environment |
| --- | --- | ---: | --- |
| Server | `NYU_server` | 63 | Challenge services hosted in isolated Docker Compose networks |
| Offline | `NYU_offline` | 57 | File-based challenges in a network-disabled analysis container |

The agent uses Bash and Python tools in a dedicated Kali Linux container based
on `aisiuk/evals-cybench-agent-sandbox`. Public challenge files are copied tinto the agent’s container at `/ctf_files`. The agent is instructed to find the flag and submit it using
`submit()`. Inspect's `includes()` scorer checks whether the submitted answer
contains the expected flag; it does not assess the exploit method or reasoning.
Results describe this selected subset, rather than the complete original test set.

## Installation

Python 3.11 or newer, Git, and Docker with Docker Compose are required. Docker
must be running and accessible to your user for **both** evaluation modes.
Clone the repository and install the project with [uv](https://docs.astral.sh/uv/):

```bash
git clone https://github.com/AI-Sec-dev/inspect-eval-nyu_ctf_bench.git
cd inspect-eval-nyu_ctf_bench
uv sync
```

Initial setup requires network access to download the dataset and pull or build
container images. During evaluation, the analysis container has no internet
access; server mode permits communication with the challenge services.

## Usage

Set the credentials required by your model provider, then run either mode:

```bash
# Evaluate server-backed challenges
uv run inspect eval nyu_ctf_bench/NYU_server --model <provider/model>

# Evaluate offline, file-based challenges
uv run inspect eval nyu_ctf_bench/NYU_offline --model <provider/model>

# Limit an evaluation to ten samples
uv run inspect eval nyu_ctf_bench/NYU_offline --model <provider/model> --limit 10

# Evaluate a specific sample within server mode
uv run inspect eval nyu_ctf_bench/NYU_server --model <provider/model> --sample-id 0

# Adjust the agent's attempt, message limits and token limit
uv run inspect eval nyu_ctf_bench/NYU_server --model <provider/model> -T max_attempts=2 -T max_messages=30 --token-limit 500000

# Rebuild cached task records and sandbox configurations
uv run inspect eval nyu_ctf_bench/NYU_offline --model <provider/model> -T force_rebuild=true
```

For example, with a mock model:

```bash
uv run inspect eval nyu_ctf_bench/NYU_server --model mockllm/model
```

Each Bash or Python tool call has a 180-second timeout.

Inspect saves evaluation logs under `logs/` by default. View them with:

```bash
uv run inspect view
```

## Dataset and sandbox preparation

The loader downloads the [upstream dataset](https://github.com/NYU-LLM-CTF/NYU_CTF_Bench)
on first use. It defaults to tag `v20250206` and verifies a newly cloned checkout
against commit `1dc13a0dc41a71504f727649679e2b5a6d0cb1b1`.
Existing download directories are reused without repeating commit verification.

Dataset files live under `nyu_ctf_bench/` in the platform-specific
`inspect_evals` cache directory, typically `~/.cache/inspect_evals/` on Linux.
Generated sample records are cached separately as `tasks_server.json` and
`tasks_offline.json`. Sample IDs are zero-based integers assigned after filtering,
separately for each mode; they can change if the selected challenge set changes.

For server challenges, preparation modifies the cached Compose files in place:

- All declared networks are made internal, and an internal default network is added.
- Host port publication and service restart policies are removed.
- A dedicated agent service runs the tools and joins `ctfnet` when available,
  otherwise the default network. It does not join private backend networks.
- Only files explicitly declared as challenge artifacts are copied to the agent.

Offline challenges use the bundled Compose configuration with `network_mode: none`.

## Exclusions

The selection rules prioritize host safety and reproducibility:

- Fourteen known-incompatible challenges are explicitly excluded:
  `Philanthropy`, `rainbow_notes`, `Triathlon or Sprint?`, `krypto`, `chatterbox`,
  `scp-terminal`, `Snail Race 1`, `Shark Facts`, `blox2`, `pwnvoltex`,
  `NERV Center`, `sourcery`, `Not Too Taxing`, and `ezMaze`. These exclusions
  cover known compatibility issues, including unsupported external dependencies.
- Server challenges are excluded if their Compose services use `privileged: true`,
  mount `/var/run/docker.sock`, or add the `SYS_ADMIN` or `NET_ADMIN` capabilities.
- Challenges are excluded if any file declared in `challenge.json` is missing.
  Currently, this affects `Forensings`, whose `forensings.zip` is unavailable.
- Server mode includes only containerized challenges. Offline mode includes only
  non-containerized challenges with local challenge files, so challenges without
  either containers or files are omitted.

These categories overlap. For example, `Triathlon or Sprint?` is explicitly
excluded and also fails the Compose security check. Exclusion counts should
therefore not be added together.

## Development

```bash
uv sync
uv run pytest tests/test_nyu_ctf_bench.py
uv run ruff check src/nyu_ctf_bench tests/test_nyu_ctf_bench.py
uv run ruff format --check src/nyu_ctf_bench tests/test_nyu_ctf_bench.py
```

The tests cover challenge metadata and endpoints, dataset selection, public file
mapping, Compose security checks and network isolation, cache rebuilding, task
configuration, and download revision verification. They use temporary fixtures
and mocked downloads, requiring neither Docker nor model API credentials.

## Citation

If you use this evaluation, cite the original
[NYU CTF Bench paper](https://arxiv.org/abs/2406.05590):

```bibtex
@article{shao2024nyuctfbench,
  title = {{NYU CTF Bench}: A Scalable Open-Source Benchmark Dataset for Evaluating {LLMs} in Offensive Security},
  author = {Shao, Minghao and Jancheska, Sofija and Udeshi, Meet and Dolan-Gavitt, Brendan and Xi, Haoran and Milner, Kimberly and Chen, Boyuan and Yin, Max and Garg, Siddharth and Krishnamurthy, Prashanth and Khorrami, Farshad and Karri, Ramesh and Shafique, Muhammad},
  year = {2024},
  eprint = {2406.05590},
  archivePrefix = {arXiv},
  primaryClass = {cs.CR}
}
```

## License

This implementation is licensed under the [MIT License](LICENSE). Downloaded
challenge files and container images may be subject to separate upstream terms;
see the [NYU CTF Bench repository](https://github.com/NYU-LLM-CTF/NYU_CTF_Bench)
for dataset licensing information.
