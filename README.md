# AssessPilot

AI agents that draft IT security assessments (CIA classification plus control mapping to
ISO/IEC 27001:2022, OWASP ASVS 4.0.3 and NIST AI RMF) from a repository and its design
documents. n8n orchestrates the agents. Every conclusion cites code that is verified
automatically, and nothing is published until a human approves it.

```
 n8n webhook ──► Ingest (read-only) ──► Inventory agent ──► CIA agent ──► Control-mapping agent
                   │ secrets redacted                                         │
                   │ prompt injection neutralised                             ▼
                   │                                                   Evidence verifier
                   ▼                                                 (quote must exist at
               audit log (hash-chained) ◄── every stage ──────────     cited file:line)
                                                                              │
                                     Draft report ──► human review page ──► approve / reject
                                                                              │ approver key
                                                                              ▼
                                                          Publish (report file / GitLab issue)
```

## What each part does

| Part | File | Purpose |
|---|---|---|
| Ingestion | `assesspilot/ingest.py` | Reads a local directory, a git URL or `gitlab:group/project`. GitLab projects are read as one archive per commit (cached), which avoids rate limits. A token with any scope other than `read_*` is refused. |
| Input filter | `assesspilot/guardrails.py` | Redacts secrets line by line, so line numbers stay valid. Replaces prompt-injection lines (for example "ignore previous instructions…") before any model sees them. |
| Agents | `assesspilot/agents.py` | Three narrow agents, each with its own prompt and JSON schema: **inventory**, **CIA classification** and **control mapping**. Control mapping asks for a verdict on every control, in five groups, each with its own keyword-ranked file selection. The AI governance group only runs when the code uses an AI model. |
| LLM | `assesspilot/llm.py` | Azure OpenAI in JSON mode. It requests temperature 0 and a fixed seed, and drops both if the model rejects them. If the output fails schema validation, it retries once and passes the validation error back to the model. |
| Rule baseline | `assesspilot/heuristics.py` | Produces the same three outputs from regex rules, with no LLM. Used offline and as the baseline in evaluation. |
| Output filter | `agents.postprocess_mapping` | Removes control IDs that are not in `controls.yaml` and redacts secrets in model output. |
| Evidence verifier | `assesspilot/evidence.py` | Each citation's quote must appear at the cited lines (±2). If none of a finding's citations verify, the finding is dropped; a CIA level with no verified citation is shown as Unverified. |
| Audit | `assesspilot/store.py` | Append-only SQLite log in which each entry hashes the previous one. `verify_chain()` detects edits. |
| Approval gate | `pipeline.decide` / `pipeline.publish` | Publishing is refused unless a named reviewer has approved the run. |
| API | `assesspilot/api.py` | Endpoints that n8n calls, plus an HTML review page. |
| Workflow | `n8n/assesspilot_workflow.json` | 12-node n8n workflow: webhook → 5 agent stages → draft → wait for human → approved? → publish. |

**Least privilege, two roles.** n8n holds `ASSESSPILOT_API_KEY`, which lets it run stages and publish runs that are already approved. Only human reviewers hold `ASSESSPILOT_APPROVER_KEY`, which is the only way to approve a run. The automation therefore cannot approve its own output.

## Run it

### Offline, no LLM and no n8n
```bash
pip install -r requirements.txt
python -m assesspilot.cli assess examples/sample_app --docs examples/design.md
pytest -q
```

### With Azure OpenAI
Fill in `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_API_KEY` and `AZURE_OPENAI_DEPLOYMENT` in `.env` (copy it from `.env.example`). The backend switches to `azure` automatically.

### With n8n
```bash
cp .env.example .env        # set the two keys (and Azure if wanted)
docker compose up -d --build
docker compose exec n8n n8n import:workflow --separate --input=/workflows
```
Open n8n at http://localhost:5678 and activate the workflow. Then:
```bash
curl -X POST http://localhost:5678/webhook/assesspilot \
     -H "Content-Type: application/json" \
     -d '{"source": "/app/examples/sample_app", "docs": ["/app/examples/design.md"]}'
```
The response contains a `review_url`. Open it, enter your name and the approver key, and approve or reject. Approval resumes the waiting n8n execution, which publishes the report.

## Evaluation

```bash
python eval/run_eval.py                                  # rule baseline, 3 runs per pilot
python eval/run_eval.py --backends heuristic azure       # compare with Azure OpenAI
python eval/make_worksheets.py <pilot> ...               # blank label file + worksheet for a human
```

The pilots are open-source projects pinned to a commit (`eval/pilots.yaml`): OWASP PyGoat, DVPWA, OWASP Juice Shop, the FastAPI full-stack template and two projects read through the GitLab API (simply-vulnerable-notes, vuln-flask-web-app), plus the bundled demo app.

| Dimension | Metric |
|---|---|
| Accuracy | CIA level accuracy, per-control status accuracy, gap precision and recall. Computed only against label files marked `status: verified`. |
| Consistency | CIA agreement across repeated runs; mean pairwise Jaccard of the (control, status) sets |
| Security alignment | Share of proposed control IDs that are in the catalog; share of citations that verify; share of findings supported by evidence |
| Effort | Seconds and tokens per run; `manual_minutes − review_minutes`, both measured by a person and recorded in the label file |

Label files for the external pilots start blank and need a person to complete them, so accuracy is currently only available for the demo app, whose issues were planted by the same author as the rules. That makes its scores optimistic, especially for the rule baseline.

Earlier results are kept in `eval/results/`: `results_v1_freeform` (first prompt design), `results_v2_bug_id_echo` (invalid: a parsing bug discarded most answers) and `results_v3_grouped` (current design).

## Limitations
- The rule baseline is regex-based. It flags patterns, not data flow, so it misses things like a missing role check and produces false positives such as the word "token" in an unrelated log line.
- Evidence verification proves that a quote exists at the cited lines, not that the conclusion drawn from it is correct. That is the reviewer's job.
- The control catalog is a curated subset (13 ISO 27001 controls, 17 ASVS requirements, 5 NIST AI RMF subcategories).
- For large repositories, at most 400 files are read (security-relevant files first). Inventory sees the first 60k characters' worth of files; CIA and each control group see about 60k characters of the files most relevant to them.
- LLM results still vary between runs, CIA levels in particular.
- `assesspilot.db` stores the original, unredacted source files. Models and reports only use the filtered copy, but the database itself should be treated as sensitive.
- The review page (`GET /runs/{id}/review`) shows the draft without a key; only submitting a decision needs the approver key. n8n also keeps the draft in its execution history. Deploy behind access control.
