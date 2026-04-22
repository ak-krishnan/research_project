# Ready-to-Use Prompt for Gemini Pro

## Which Tool for What

| Task | Use This |
|---|---|
| **Find papers & citations** | Perplexity Pro |
| **Write the paper** | Gemini Pro |
| **Verify technical accuracy** | Me (Antigravity) |

**Order: Perplexity first → Gemini second → Me to verify**

---

## Step 1: Perplexity Pro Queries (do these first)

Copy-paste each one into Perplexity:

```
1. "LLM-based static analysis false positive reduction research papers 2023-2025"
2. "IRIS NDSS 2025 LLM vulnerability detection"
3. "Retrieval Augmented Generation for code analysis security papers"
4. "Semgrep false positive rates academic evaluation"
5. "OWASP benchmark for SAST tool evaluation research papers"
6. "Christakis Bird ICSE 2016 static analysis developers"
```

Save every paper title, author list, year, and venue. You'll paste them into the Gemini prompt below.

---

## Step 2: Gemini Pro — THE PROMPT

> [!IMPORTANT]
> Don't dump the entire thing at once. Split into 2-section chunks (I, II first → then III, IV → then V, VI, VII). Iterate each section before moving on.

### Prompt Part 1: Setup + Sections I & II

```
You are writing an IEEE-formatted computer science research paper. Use formal 
academic English. Do NOT invent citations — use ONLY references I provide.

TITLE: "Repository-Level Semantic Verification: A Multi-Stage LLM Framework 
for SAST False Positive Reduction"

AUTHORS: [Your Name], [Advisor Name if any], [Institution]

Write Sections I and II using these details:

=== SECTION I: INTRODUCTION ===

Key arguments to make:
- SAST tools (Semgrep, CodeQL, Fortify) are essential for proactive vulnerability 
  detection but produce 20-70% false positives depending on the codebase
- This causes "alert fatigue" — developers ignore real vulnerabilities because 
  they're buried in noise
- Recent LLM-based approaches (IRIS, VulnLLMEval) improve triage but are 
  BOTTLENECKED by localized analysis — they see only isolated code snippets 
  (50-200 lines), missing cross-file mitigations
- Examples of what they miss: middleware sanitizers in separate files, 
  WAF/reverse proxy configs, security headers set in server config
- WE PROPOSE: a 2-phase pipeline that uses Retrieval-Augmented Generation (RAG) 
  to give the LLM repository-wide context during verification

Our contributions (as a numbered list):
1. A 2-phase architecture separating high-recall scanning from semantic verification
2. A CWE-aware RAG retrieval strategy that searches for vulnerability-specific 
   mitigation patterns across the full repository
3. A strict anti-hallucination verification prompt with 7 explicit rules to 
   prevent the LLM from fabricating mitigations
4. Empirical evaluation on OWASP Juice Shop demonstrating false positive 
   reduction while maintaining recall

=== SECTION II: BACKGROUND AND MOTIVATION ===

II.A: Limitations of Deterministic Taint Analysis
- SAST tools work via: pattern matching on ASTs, taint tracking on data-flow graphs
- They analyze individual files or function-level data flows (localized scope)
- Cannot see: WAF rules, reverse proxy configs, middleware in other files, 
  security headers, architectural patterns
- Result: over-reporting with high FP rates
- Cite: NIST SATE reports, Chess & West "Secure Programming with Static Analysis"

II.B: Limitations of LLM-Based Vulnerability Analysis
- Recent work uses LLMs to understand code semantics better than regex/AST matching
- Key limitation: context window bottleneck — LLM receives a snippet, not the repo
- Example: LLM sees eval(userInput) in isolation → calls it vulnerable. 
  But a middleware in another file strips dangerous characters → it's mitigated.
  The LLM can't know this.
- This is the GAP our work addresses

REFERENCES I HAVE (use only these):
[PASTE YOUR PERPLEXITY RESULTS HERE]

FORMAT: IEEE conference paper, formal tone, ~2.5 pages for these two sections.
Include \cite{} placeholders matching my reference list.
```

### Prompt Part 2: Sections III & IV

```
Continue the paper. Write Sections III and IV.

=== SECTION III: PROBLEM FORMULATION ===

III.A: Vulnerability Detection as Graph Analysis
Use formal notation:
- Define: S = {source nodes} = user inputs (req.query, req.body, req.params)
- Define: K = {sink nodes} = dangerous APIs (eval(), sequelize.query(), 
  res.sendFile(), innerHTML)
- A vulnerability exists iff there exists a path P: s → k where s ∈ S, k ∈ K, 
  and P passes through NO sanitizer node
- SAST tools find candidate paths P̂ but cannot verify full sanitizer coverage
- Formally: FP = {p ∈ P̂ | ∃ sanitizer(p) that SAST cannot observe}

III.B: Need for Repository-Level Context
Sanitizers exist at 4 architectural layers:
1. Inline (same function) — SAST catches these
2. Same-file (middleware in same module) — SAST sometimes catches
3. Cross-file (separate middleware, config files) — SAST misses
4. Infrastructure (WAF, reverse proxy, network policies) — SAST always misses
Our system targets layers 2-3 via RAG retrieval.

=== SECTION IV: PROPOSED METHODOLOGY ===

IV.A: System Architecture
Describe a 2-phase pipeline with a diagram placeholder:
[Figure 1: System Architecture — Repository → Phase 1 (Semgrep + Dedup + Triage) 
→ Phase 2 (RAG Verification) → Classified Results]

IV.B: Phase 1 — High-Recall Deterministic Scanning
- Tool: Semgrep OSS with --config auto (all rules enabled for maximum recall)
- Output: structured JSON with CWE labels, file paths, line numbers, severity
- Post-processing:
  * Parse into normalized format: (file, line, CWE, vulnerability_class, message)
  * Location-based deduplication: unique key = (file, line, vuln_type)
  * Lightweight scout triage removes malformed entries
- Design rationale: maximize recall at this stage, let Phase 2 handle precision

IV.C: Phase 2 — Repository-Level Context Verification (MAIN CONTRIBUTION)
Detail each sub-component:

1. Semantic Chunking:
   - Full repository code loaded via DirectoryLoader
   - Split into 1000-character chunks with 200-character overlap
   - Using LangChain's RecursiveCharacterTextSplitter

2. Vector Store:
   - Chunks embedded using HuggingFace all-MiniLM-L6-v2 (384-dim embeddings)
   - Stored in ChromaDB for efficient similarity search
   - Retriever configured with k=8 (top 8 most relevant chunks per query)

3. CWE-Aware Retrieval (KEY INNOVATION):
   Instead of generic keyword search, we use a CWE → mitigation pattern mapping:
   - CWE-89 (SQLi): "parameterized query", "prepared statement", "bind", 
     "sequelize replacement", "escape"
   - CWE-79 (XSS): "DOMPurify", "sanitize-html", "escapeHtml", 
     "Content-Security-Policy", "helmet"
   - CWE-798 (Hardcoded Secrets): "process.env", "vault", "key rotation", 
     "environment variable"
   - CWE-73 (Path Traversal): "path.resolve", "whitelist", "path.normalize", 
     "realpath"
   - CWE-611 (XXE): "disableEntityExpansion", "noent: false", "libxmljs safe"
   - CWE-601 (Open Redirect): "allowlist", "url whitelist", "redirect validation"
   
   The retrieval query combines the vulnerability description with CWE-specific 
   mitigation terms, ensuring the LLM receives contextually relevant code.

4. Strict-Neutral Verification Prompt:
   The LLM receives: flagged code + retrieved context + 7 anti-hallucination rules:
   Rule 1: Test files (.spec.*, .test.*) are NOT mitigations
   Rule 2: If you cannot SEE the actual mitigation code in the context, 
           it does NOT exist — do not assume
   Rule 3: String length truncation is NOT SQL injection mitigation
   Rule 4: localStorage/sessionStorage is NOT secrets management
   Rule 5: Only parameterized queries or prepared statements count for CWE-89
   Rule 6: Incomplete or bypassable mitigations → still VALIDATED (vulnerable)
   Rule 7: When uncertain → default to VALIDATED, not MITIGATED
   
   Output: VALIDATED (confirmed vulnerable) or MITIGATED (FP) with confidence 
   score and evidence

5. LLM Configuration:
   - Model: llama-3.1-8b-instant via Groq API
   - Temperature: 0.0 (deterministic)
   - One finding per API call (no batching) for maximum attention

FORMAT: IEEE, ~3-4 pages for these two sections. Include [Figure 1] and 
[Figure 2] placeholders. Use formal notation in Section III.
```

### Prompt Part 3: Sections V, VI, VII

```
Continue the paper. Write Sections V, VI, and VII.

=== SECTION V: EXPERIMENTAL EVALUATION ===

V.A: Experimental Setup
- Dataset: OWASP Juice Shop v17.x — intentionally vulnerable Node.js/TypeScript 
  web application with ~100 documented security challenges across 14 CWE categories
- Ground Truth: manually cross-referenced all Semgrep findings against official 
  Juice Shop challenge documentation
- Tools: Semgrep 1.x (OSS), llama-3.1-8b-instant (Groq), ChromaDB, 
  HuggingFace all-MiniLM-L6-v2
- Environment: macOS, Python 3.11, Streamlit UI

V.B: Evaluation Metrics (define formally)
- Precision = TP / (TP + FP)
- Recall = TP / (TP + FN)
- F1 = 2 × (Precision × Recall) / (Precision + Recall)
- FP Reduction Rate = (FP_phase1 - FP_phase2) / FP_phase1 × 100

V.C: Phase 1 Results
- Semgrep produced 38 raw findings
- After deduplication: 36 unique findings
- Ground truth classification: 29 True Positives, 7 False Positives
- Semgrep-alone Precision: 80.6% (29/36)
- False positive breakdown:
  * 3 test files (.spec.ts) with mock JWT tokens
  * 2 ReDoS flags on server-controlled (non-user) input
  * 1 benign eval() on auto-generated CAPTCHA math expressions
  * 1 informational console.log format string with no exploit path
- Vulnerability classes detected: SQL Injection (7), XSS (6), Path Traversal (4), 
  Directory Listing (4), Hardcoded Secrets (3), XXE (1), Open Redirect (1), 
  RCE (1), Eval Injection (1), Prototype Pollution (1), Property Injection (1)

V.D: Phase 2 Results
[PLACEHOLDER — insert actual results after running experiments]
- Phase 2 Precision: [X]%
- FP Reduction Rate: [Y]%
- Table 2: Per-finding classification (VALIDATED vs MITIGATED vs ground truth)
- Correctly identified FPs: [N]/7
- False negatives (TPs wrongly mitigated): [M]/29

V.E: Case Study
[PLACEHOLDER — pick one example where RAG correctly identified a FP, 
e.g., the test file JWT tokens, and walk through the retrieval + reasoning]

=== SECTION VI: DISCUSSION AND LIMITATIONS ===

Discuss these points:
1. Computational overhead: RAG retrieval + LLM inference adds ~3-12s per finding
2. API rate limiting: Cloud LLM APIs impose daily token limits (100k-500k TPD), 
   bottlenecking large-scale analysis
3. Embedding limitations: all-MiniLM-L6-v2 is general-purpose, not security-tuned; 
   may miss domain-specific semantic connections
4. Retrieval precision: ChromaDB top-k may return irrelevant chunks for large repos
5. Single-benchmark evaluation: results are from one intentionally vulnerable 
   application; generalization to production codebases needs further study
6. LLM hallucination: despite 7 anti-hallucination rules, LLMs can still 
   occasionally fabricate evidence
7. SAST inherent limitations: cannot detect business logic flaws, broken 
   authorization, OSINT-based vulnerabilities, or NoSQL injection without 
   specific rule sets
8. The system targets layers 2-3 (same-file and cross-file mitigations) but 
   cannot reason about layer 4 (infrastructure: WAFs, network policies)

=== SECTION VII: CONCLUSION ===

Summarize:
- We presented a 2-phase framework combining deterministic SAST with 
  RAG-augmented LLM verification
- Key innovation: CWE-aware retrieval that searches for vulnerability-specific 
  mitigation patterns across the full repository
- Results: improved precision from 80.6% to [X]% on OWASP Juice Shop
- The strict anti-hallucination prompt prevents the most common LLM failure modes

Future Work:
1. Multi-language evaluation (Java via WebGoat, PHP via DVWA)
2. Fine-tuned security-specific embeddings (replacing general-purpose MiniLM)
3. CI/CD integration for automated pipeline execution on pull requests
4. Ablation studies on retrieval k values and chunk sizes
5. Evaluation on real-world CVE-listed open source projects

FORMAT: IEEE, ~3 pages. Include [Table 1] and [Table 2] placeholders.
Leave [PLACEHOLDER] markers where noted — I will fill these after experiments.
```

---

## Step 3: Come Back to Me For

After Gemini writes the draft, bring it back here and I'll:
1. ✅ Verify the methodology matches your actual `utils.py` code
2. ✅ Generate the system architecture diagram
3. ✅ Fill in the [PLACEHOLDER] results after you run the pipeline
4. ✅ Fix any technical inaccuracies Gemini introduced
