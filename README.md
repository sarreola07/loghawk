# LogHawk 🦅

**An AI-powered security log analyzer.** LogHawk reads security log entries and uses a large language
model (Qwen Coder, served through an OpenAI-compatible API) to label each one **BENIGN**, **SUSPICIOUS**,
or **MALICIOUS** with a one-sentence reason, then writes a Markdown security assessment report.

## How it works

1. **Read:** keeps only real, timestamped log entries and takes an evenly spaced sample across the file.
2. **Triage:** sends each line to the model with a strict `LABEL:` / `REASON:` output format.
3. **Parse defensively:** an `Enum` + `dataclass` model the result; regexes pull out the fields, and anything
   off-format falls back to `UNKNOWN` instead of crashing.
4. **Report:** writes `assessment.md` with a summary table and per-entry findings (hostname/username redacted).

## Files

| File | What it is |
|---|---|
| `LogHawk.ipynb` | The tool: connection, model helper, triage function, report writer |
| `assessment.md` | Example security assessment generated from a real macOS log |

## Run it

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

Create a `.env` file (never commit it):

```
GPUSTACK_BASE_URL=<your OpenAI-compatible endpoint ending in /v1>
GPUSTACK_API_KEY=<your key>
```

Export a log (macOS) and open the notebook:

```bash
/usr/bin/log show --predicate 'process == "sudo" OR process == "sshd" OR process == "loginwindow" OR eventMessage CONTAINS[c] "authentication"' --last 6h --style syslog > security_log.txt
jupyter lab LogHawk.ipynb
```

## Security notes

- The API key lives only in a git-ignored `.env` file.
- Raw security logs are git-ignored; only the generated report is published.
- AI labels are a triage aid, not a verdict. A human analyst should review anything SUSPICIOUS or MALICIOUS.

*Built for IS2083 Advanced Scripting, UTSA.*
