# audit

An 8-stage vulnerability-discovery agent, driven by your **Claude Pro / Max
subscription** through the official Claude Code Agent SDK. Many narrow agents,
deliberate disagreement, and an explicit reachability gate.

MIT-licensed. No API key needed if you already use `claude login`.

## Origin

This project is a from-scratch reimplementation of the pipeline described in
Cloudflare's [Project Glasswing](https://blog.cloudflare.com/cyber-frontier-models/)
post, which tested Anthropic's Mythos preview LLM against Cloudflare's own
codebase. The blog argues that real-world vulnerability discovery does **not**
come from asking one big model "find bugs here" — it comes from:

1. **Many narrow agents** working in parallel on tightly-scoped questions
   ("Look for command injection in this specific function, with this trust
   boundary above it") rather than one exhaustive agent.
2. **Deliberate disagreement** — a second agent, on a different model, that
   tries to *disprove* the first agent's findings.
3. **A reachability trace** as the gating step — most "is this code buggy?"
   findings are noise unless an attacker-controlled input can actually reach
   the sink from outside the system.
4. **A feedback loop** so reachable bugs in one place automatically seed
   hunts for the same pattern elsewhere.

This repo packages that pipeline into a runnable agent. The Cloudflare post
showed the architecture; this codebase ships the prompts, schemas, state
store, and orchestrator.

## The 8 stages

![Vulnerability discovery harness — 8 stages](https://raw.githubusercontent.com/evilsocket/audit/main/docs/pipeline.png)

<sub>Diagram from Cloudflare's [Project Glasswing](https://blog.cloudflare.com/cyber-frontier-models/) post, reproduced here for reference.</sub>

| # | Stage    | Default model | Purpose |
|---|----------|---------------|---------|
| 1 | Recon    | Opus 4.7  | Map the repo, emit narrowly-scoped Hunt tasks |
| 2 | Hunt     | Sonnet 4.6 | One attack class per agent; compile/run PoCs |
| 3 | Validate | Opus 4.7  | Adversarial re-read; tries to **disprove** (different model from Hunt) |
| 4 | Gapfill  | Sonnet 4.6 | Re-queue under-covered areas |
| 5 | Dedupe   | Sonnet 4.6 | Cluster findings by root cause |
| 6 | Trace    | Opus 4.7  | Prove attacker-controlled input reaches the sink |
| 7 | Feedback | Sonnet 4.6 | Turn reachable traces into new Hunt tasks |
| 8 | Report   | Sonnet 4.6 | Schema-validated structured report |

Each stage is one markdown prompt in `prompts/` + one JSON Schema in
`schemas/`. The orchestrator passes the schema into the system prompt so
every output is shape-stable on the first try.

## Quickstart

```bash
# 1. Install
python -m venv .venv && source .venv/bin/activate
pip install -e .

# 2. Auth (pick one)
#    (a) Already logged in via claude login? You're done.
#    (b) Or generate a 1-year OAuth token for CI / non-interactive use:
claude setup-token
echo "CLAUDE_CODE_OAUTH_TOKEN=<paste>" > .env

# 3. Verify
audit auth-check

# 4. Run
audit run --repo /path/to/target --run-id my-run
audit status --run-id my-run
audit report --run-id my-run --format md > report.md
```

By default the agent uses **subscription billing** via your Claude.ai
login — it does **not** call the metered Anthropic API. The on-disk auth
module scrubs `ANTHROPIC_API_KEY` from the environment so it can't
silently route around the OAuth flow.

## Local dashboard

`audit` can launch a local read-only dashboard for browsing historical runs,
tasks, findings, costs, artifacts, and final reports.

Install the optional dashboard dependencies:

```bash
pip install -e ".[dashboard]"
```

If you also want the test dependencies:

```bash
pip install -e ".[dev,dashboard]"
```

Start the dashboard:

```bash
audit dashboard
```

Or, if your shell has another command named `audit`, run the module directly:

```bash
python -m audit.cli dashboard
```

Then open:

```text
http://127.0.0.1:8765
```

The dashboard reads the existing local `state.db`, `results/`, and `work/`
directories. It does not start new scans yet and does not modify run state.

### Dashboard safety

The dashboard is intended for local use and binds to `127.0.0.1` by default.

Scan artifacts can contain source snippets, prompts, tool outputs, file paths,
and any sensitive data the agent read during the scan. Do not expose the
dashboard on an untrusted network unless you have added your own access
controls and artifact redaction.

## Using a different model / provider

The auth module picks one of three modes, in this order:

1. **LLM gateway** (OpenRouter, custom proxy, etc.) — when
   `ANTHROPIC_BASE_URL` points away from `anthropic.com` AND
   `ANTHROPIC_AUTH_TOKEN` is set. The gateway env is left intact;
   only `ANTHROPIC_API_KEY` is scrubbed (it would otherwise outrank the
   gateway token).
2. **Subscription OAuth (headless)** — `CLAUDE_CODE_OAUTH_TOKEN` from
   `claude setup-token`. Best for CI.
3. **Subscription OAuth (interactive)** — `~/.claude/.credentials.json`
   from `claude login`. Best for local dev.

### OpenRouter

OpenRouter exposes Claude-compatible Anthropic-API endpoints behind its
own credit system; that lets you spend OpenRouter credits instead of an
Anthropic subscription, and gives you access to Sonnet/Opus *and* other
models through the same SDK path. See [OpenRouter's Agent SDK guide](https://openrouter.ai/docs/guides/community/anthropic-agent-sdk).

```bash
export ANTHROPIC_BASE_URL="https://openrouter.ai/api"
export ANTHROPIC_AUTH_TOKEN="$OPENROUTER_API_KEY"
export ANTHROPIC_API_KEY=""           # must be explicitly empty / unset
# optional: pick a non-Anthropic model
export ANTHROPIC_MODEL="anthropic/claude-sonnet-4-6"
# or e.g.: ANTHROPIC_MODEL="openai/gpt-5"
#         ANTHROPIC_MODEL="google/gemini-2.5-pro"
#         ANTHROPIC_MODEL="qwen/qwen3-coder-480b"

audit auth-check                       # confirms "using LLM gateway at https://openrouter.ai/api"
audit run --repo /path/to/target --run-id orun --max-cost-usd 30
```

Caveats:

- Per-stage model overrides in `config/stages.yaml` are model **names**
  (e.g. `claude-opus-4-7`); OpenRouter accepts slash-prefixed forms like
  `anthropic/claude-opus-4-7`. Edit the YAML if you want different
  providers per stage. Otherwise `ANTHROPIC_MODEL` forces every stage
  onto one model.
- Non-Claude models may not produce schema-compliant JSON as reliably.
  The runner's schema-validation + repair turn still applies; quality
  varies by model.
- Tool-use semantics (Read/Grep/Glob/Bash) are part of the Claude Code
  CLI, not the model — they work as long as the gateway speaks the
  Anthropic Messages API.

### Other gateways / cloud providers

Same recipe — anything that exposes the Anthropic Messages API at a URL
+ a bearer token works:

```bash
export ANTHROPIC_BASE_URL="https://your-proxy.example.com"
export ANTHROPIC_AUTH_TOKEN="$YOUR_TOKEN"
unset ANTHROPIC_API_KEY
```

For Amazon Bedrock / Google Vertex / Microsoft Foundry, Claude Code has
first-class env-var flags (`CLAUDE_CODE_USE_BEDROCK=1` etc.) that
outrank everything else. See the [Claude Code auth docs](https://code.claude.com/docs/en/authentication).

## Cost containment

A real production codebase can produce 15-50 Hunt tasks and 25+ findings to
validate. At default concurrency this gets expensive. Flags to keep it sane:

```bash
audit run --repo /path/to/target \
  --max-concurrency 1 \           # one claude subprocess at a time
  --max-recon-tasks 15 \          # cap initial Hunt fanout
  --max-cost-usd 30               # abort cleanly if exceeded
```

The budget guard fires between *and* within stages — a per-task check in
Hunt cooperatively aborts rather than running 30 more tasks past the cap.

## Live-target reproduction (optional)

If the target has a running deployment, point the agents at it. Hunt now
**reproduces** each finding against the live service instead of compiling
a local PoC, Validate **rejects** findings that don't reproduce, and Trace
**confirms** reachability with real HTTP round-trips. The static path
remains available — these flags are opt-in.

```bash
audit run --repo /path/to/target --run-id live \
  --max-concurrency 1 --max-cost-usd 30 \
  --target-url http://server.local:8888 \
  --target-creds email=admin@system.com \
  --target-creds password=changechangeme
```

Rules the agents follow when `--target-url` is set:

- Network egress is restricted to that host + `127.0.0.1`. No other external
  hosts.
- A finding that doesn't reproduce against the live target is dropped or
  rejected (depending on stage) — "no fabrication".
- Credentials flow into every relevant stage's user_input as a dict.

## Scope notes (optional)

Targets often have intentionally-loose-by-design surfaces that aren't bugs
(e.g. plaintext API keys when that's a feature, test-only Mailpit endpoints,
anonymous-analytics ingest). Drop them in a text file and pass it in — the
notes are appended verbatim to every stage's user_input, and Recon / Hunt /
Validate honor exclusions you list.

```bash
audit run --repo /path/to/target --scope-notes target_scope.md
```

Example `target_scope.md`:

```markdown
- Mailpit (port 1025) is test-only; ignore.
- Plaintext API keys in the database are a required feature.
- Don't flag rate-limit absence on anonymous /ping endpoints.
- Only consider critical/high severity.
```

## Recon mines git history

Recon greps the git history for past security patches
(`CVE`, `sec:`, `fix.*auth`, `sanitize`, …) — patched files are hardened,
but **sibling files with the same idiom often aren't**. Findings get seeded
against the unpatched copies. Adds zero cost on repos without that pattern;
catches real cross-component bugs on repos that have it.

## Logic chains

The pipeline's default is one-attack-class-per-task (the Cloudflare paper's
narrow-scope rule). Recon can also emit `logic_chain` tasks for high-impact
multi-component paths (auth-bypass + IDOR + path-traversal that compose into
RCE, etc.) — one chain per task, with the `scope_hint` naming the specific
chain. This is the one allowed exception to single-attack-class scoping.

## Layout

```
prompts/        8 stage prompts (markdown, loaded as system prompts)
schemas/        9 JSON schemas — every agent output is validated
config/         stages.yaml — model + concurrency + tool allowlist per stage
audit/          Python package
  auth.py       OAuth check + ANTHROPIC_API_KEY scrubbing
  state.py      SQLite DAO (runs, tasks, findings, traces, dedupe, costs)
  runner.py     claude-agent-sdk wrapper with schema validation + repair turn
  orchestrator.py pipeline driver
  stages/       one module per stage
  dashboard/    optional local web dashboard
work/           per-Hunt-task scratch dirs (sandbox for PoC compile/run)
results/        JSONL artifacts per stage + final report.json
state.db        SQLite (gitignored)
```

## Safety

Hunt agents have Bash and run inside per-task scratch dirs. They are **not**
sandboxed at the OS level. Run the audit inside a disposable VM or container
when you don't trust the target source — a target with malicious build
scripts could otherwise execute on your host during PoC compilation.

The agent reads everything you `--add-dir`, including any `.env` or
`secrets/` directories in the target. Outputs land in `results/<run-id>/`
which is `.gitignore`d but **not** scrubbed of those reads.

The dashboard is also local-first and read-only, but it can display the same
sensitive artifacts. Keep it bound to `127.0.0.1` unless you have added
access controls and artifact redaction.

## License

[MIT](LICENSE). Reuse freely. No warranty.

## Acknowledgements

- The pipeline design is from Cloudflare's [Project Glasswing](https://blog.cloudflare.com/cyber-frontier-models/)
  blog post. The credit for the architecture goes there.
- Built on the official [Claude Code Agent SDK](https://code.claude.com/docs/en/agent-sdk/overview).