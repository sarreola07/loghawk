# Demo

A short walkthrough of LogHawk (`logtriage.py`) running end to end.

**Recording:** DEMO_LINK_HERE

## What the demo shows (2 to 3 minutes)
1. Install and configure (the key is set off-screen and never shown):
   ```bash
   pip install -r requirements.txt
   export QWEN_BASE_URL="http://your-server:8000/v1"
   export QWEN_API_KEY="your-api-key"
   ```
2. The help, so viewers see the options:
   ```bash
   python logtriage.py --help
   ```
3. A full run on the SSH/sudo log, generating a Sigma rule:
   ```bash
   python logtriage.py --input ssh_auth_log.txt --output results.csv --json results.json --rule sigma --rule-out rule.txt
   ```
4. The output files:
   ```bash
   head -5 results.csv
   cat rule.txt
   ```
5. The tests passing:
   ```bash
   python -m pytest
   ```
6. The Semgrep static analysis scan:
   ```bash
   semgrep scan --config auto logtriage.py
   ```

## Example run

```
$ python logtriage.py --input ssh_auth_log.txt --output results.csv --json results.json --rule sigma --rule-out rule.txt
Connected. Model: qwen3-coder-next
Assessing 200 entries from ssh_auth_log.txt ...
  BENIGN     112
  SUSPICIOUS 80
  MALICIOUS  8
Wrote results.csv
Wrote results.json
Wrote rule.txt
```

## About the tool
LogHawk reads a security log and asks a coding model to label every entry BENIGN,
SUSPICIOUS or MALICIOUS with a severity and a reason, then writes CSV/JSON results
and a detection rule from the findings. Its prompt-injection defense layers system
rules, delimiter neutralizing and validation in code, so a log line cannot talk the
model into calling an attack benign.

**What I would improve next:** validate the generated Sigma rule automatically
(with `sigma-cli` against known-good and known-bad logs) before saving it, and
group related lines (same source IP) so the model sees an attack as a sequence
rather than one line at a time.
