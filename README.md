# LogHawk 🦅

[![CI](https://github.com/sarreola07/loghawk/actions/workflows/ci.yml/badge.svg)](https://github.com/sarreola07/loghawk/actions/workflows/ci.yml)

An AI-powered **security log triage** command-line tool. LogHawk reads a security
log file and uses a coding language model (Qwen Coder, or any OpenAI-compatible
model) to classify each entry as **BENIGN**, **SUSPICIOUS**, or **MALICIOUS**,
with a severity (1–5) and a one-sentence reason. It processes a whole file in
parallel, saves the results, and can generate a detection rule from what it finds.

_Capstone project for IS2083 Advanced Scripting at UTSA. It started as two Jupyter
notebooks (Labs 5 and 6) and ships here as one tested, packaged CLI: `logtriage.py`._

## Features
- Classifies each log entry with a label, a 1–5 severity, and a reason.
- Returns validated JSON and falls back safely to `UNKNOWN` on bad model output.
- Processes a whole log file in batch with a thread pool; one bad line never stops the run.
- Generates a detection rule (Sigma, iptables, or regex) from the findings.
- Treats log text as untrusted input, with a three-layer prompt-injection defense:
  1. rules in the **system** message, separate from the log data,
  2. `<<<` / `>>>` delimiters neutralized so a line cannot "close" its data block,
  3. output validation in code: a line with instructions aimed at the AI is never allowed to come back BENIGN.
- Ships with offline tests (a fake model, no server or key), Semgrep static analysis, and a GitHub Actions CI workflow.

## Requirements
- Python 3.9 or newer
- `pip install -r requirements.txt` (`openai` to run; `pytest` and `semgrep` for development)
- Access to an OpenAI-compatible model endpoint (a vLLM/GPUStack server, the class Qwen Coder server, etc.)

## Setup
```bash
pip install -r requirements.txt
export QWEN_BASE_URL="http://your-server:8000/v1"
export QWEN_API_KEY="your-api-key"
# optional: export QWEN_MODEL="model-id"   (default: the server's *coder* model)
```
On Windows PowerShell use `$env:QWEN_BASE_URL="..."` instead of `export`.
See `.env.example` for the variables. Never commit a real key.

## Usage
```bash
python logtriage.py --input ssh_auth_log.txt
python logtriage.py --input ssh_auth_log.txt --output results.csv --json results.json
python logtriage.py --input ssh_auth_log.txt --rule sigma --rule-out rule.txt
python logtriage.py --input ssh_auth_log.txt --limit 25 --severity-min 4
```

| Option | Default | What it does |
|---|---|---|
| `--input`, `-i` | (required) | log file to assess, one entry per line |
| `--output`, `-o` | `triage_results.csv` | CSV results |
| `--json` | none | also write JSON results |
| `--limit` | 200 | max lines to assess (each line is one model call) |
| `--max-workers` | 4 | parallel model requests |
| `--rule` | `none` | `sigma`, `iptables`, or `regex` detection rule |
| `--rule-out` | `detection_rule.txt` | where the rule is written |
| `--severity-min` | 0 | print findings at or above this severity |
| `--model` | auto | model id to use |

## Testing
The tests use a fake model, so they run with no server and no key:
```bash
python -m pytest
```
- `test_logtriage.py`: the course-provided tests (JSON parsing, fallback, validation, batch, rule).
- `test_injection.py`: injection-defense tests and an end-to-end CLI run with a fake model.

## Static analysis (Semgrep)
```bash
semgrep scan --config auto logtriage.py
```
The CI workflow runs both the tests and Semgrep on every push and pull request.

**Findings reviewed:** `logtriage.py` scans clean (0 findings). Scanning the whole
repository flagged 2 issues in the workflow itself: `actions/checkout@v4` and
`actions/setup-python@v5` were mutable tags, a supply-chain risk. Both are now
pinned to full commit SHAs, and the full scan reports 0 findings.

## Files
| File | What it is |
|---|---|
| `logtriage.py` | the tool (Labs 5 + 6 combined, with a CLI) |
| `test_logtriage.py`, `test_injection.py` | offline unit tests |
| `.github/workflows/ci.yml` | GitHub Actions: pytest + Semgrep |
| `ssh_auth_log.txt` | synthetic 200-line SSH/sudo auth log used for the sample run |
| `results.csv`, `results.json`, `rule.txt` | output of the capstone run |
| `DEMO.md` | demo recording and walkthrough |
| `Lab6.ipynb`, `LogHawk.ipynb` | the original notebook prototypes (Labs 6 and 5) |
| `triage_results.*`, `detection_rule.txt`, `assessment.md` | results from the notebook versions |

## Results from the capstone run
`python logtriage.py --input ssh_auth_log.txt --output results.csv --json results.json --rule sigma --rule-out rule.txt`
against the class `qwen3-coder-next` model:

- **Triage (200 entries):** 112 BENIGN, 80 SUSPICIOUS, 8 MALICIOUS (`results.csv`, `results.json`).
- **Detection rule (`rule.txt`):** the model correctly connected the attack chain: failed root SSH logins,
  `sudo cat /etc/shadow`, and new users created with UID/GID 0 (a backdoor account).
- **Rule review:** it is closer to real Sigma than the Lab 6 rule (it uses `message|contains` field matches
  instead of made-up `EventID`s), but it is still not deployable as is: one selection uses `and` inside a
  value (`'new user:' and 'UID=0'`), it repeats the `message|contains` key in one map, `not_contains` is not
  a Sigma modifier, and the `id` is not a real UUID. Before deployment it would need those fixes and a
  test against known-good and known-bad logs (for example with `sigma-cli`).

## Security notes
- The server URL and API key come only from environment variables; they are never hard-coded or committed.
- Log data is treated as untrusted; the layered defense resists (but cannot fully prevent) instructions hidden in the input. In Lab 6 the layered version was fooled 0/12 times, versus 6/12 for the prompt-only versions.
- The sample dataset is synthetic; raw private logs are not published.
- AI labels and generated rules are a triage aid, not a verdict. Review and test a rule before deploying it.

## License
MIT. See the `LICENSE` file.
