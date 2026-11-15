# LogHawk 🦅

An AI-powered security log triage tool. LogHawk reads security log entries and uses a
coding language model (Qwen Coder, or any OpenAI-compatible model) to classify each entry
as **BENIGN**, **SUSPICIOUS**, or **MALICIOUS**, with a severity (1–5) and a one-sentence
reason. It processes whole log files in batch, saves the results, and can generate a
detection rule (for example a Sigma rule) from what it finds.

## What it does
- Classifies each log entry (BENIGN / SUSPICIOUS / MALICIOUS) with a 1–5 severity and a reason.
- Returns validated JSON, and falls back to `UNKNOWN` when the model's reply is off-format.
- Processes a whole log file in batch with a small thread pool and saves CSV and JSON results.
- Generates a detection rule (Sigma, firewall, or regex) from the suspicious and malicious findings.
- Treats log text as untrusted input and uses a hardened prompt to resist prompt injection.
- Includes offline tests that use a fake model, so they run without a server.

## Files
| File | What it is |
|---|---|
| `Lab6.ipynb` | **LogHawk v2**: secure connection, JSON triage, batch run, rule generation, injection demo, tests |
| `triage_results.csv` / `triage_results.json` | Results of a batch run over a sample SSH/sudo auth log |
| `detection_rule.txt` | Sigma rule written by Qwen Coder from the findings |
| `LogHawk.ipynb` | LogHawk v1 (Lab 5): plain-text `LABEL:` / `REASON:` triage of a macOS log |
| `assessment.md` | Markdown assessment report produced by v1 |

## Requirements
- Python 3.9 or newer
- The `openai` package (`pip install openai`, or the notebook's `%pip install openai`)
- Access to an OpenAI-compatible model endpoint (a vLLM/GPUStack server, the class Qwen Coder server, etc.)

## Setup
Install the one dependency:

```bash
pip install openai
```

Optionally set your model endpoint and key as environment variables (never hard-code them).
If they are not set, the notebook asks for the server URL and prompts for the key with `getpass`:

```bash
export QWEN_BASE_URL="http://your-server:8000/v1"
export QWEN_API_KEY="your-api-key"
```

## Usage
Open `Lab6.ipynb` and run the cells top to bottom. Point `LOG_FILE` at a log file
(`.txt`, `.csv` or `.jsonl`, one entry per line) and the tool will assess up to 200 lines,
print a label summary, and save `triage_results.csv`, `triage_results.json` and
`detection_rule.txt`.

## Results from the sample run
Run on `ssh_auth_log.txt` (200 synthetic SSH/sudo lines) with `qwen3-coder-next`:

- **Triage:** 121 BENIGN, 69 SUSPICIOUS, 10 MALICIOUS.
- **Prompt injection:** against four attack strings (3 tries each), the naive prompt and the handout's hardened prompt were **each fooled 6/12 times**. Delimiter-escape and fake-authority attacks beat both. The layered defense in Step 10c (system/user role separation, delimiter neutralizing, and output validation in code) was **fooled 0/12 times**.
- **Detection rule review:** the generated `detection_rule.txt` captures the right story (brute force, then sudo escalation, then a UID-0 backdoor account), but it is only *Sigma-shaped*. Linux auth logs have no `EventID` field, the `condition` is not valid Sigma syntax, and the `id` is a placeholder. It would need rewriting with field matches (for example `Failed password`, `COMMAND=`, `useradd`) and testing against known-good and known-bad logs before deployment.

## Security notes
- The API key is read at runtime (`getpass`) or from an environment variable; it is never stored in the notebook or the repository.
- Log data is treated as untrusted. The hardened prompt marks it as data, wraps it in `<<< >>>` delimiters, and the reply is validated, which resists (but cannot fully prevent) instructions hidden in the input.
- Raw private logs are not published; the sample dataset used here is synthetic.
- AI labels and generated rules are a triage aid, not a verdict: review them before acting or deploying.

## License
MIT. See the `LICENSE` file.

*Built for IS2083 Advanced Scripting, UTSA.*
