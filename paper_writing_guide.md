# Research Paper Writing Guide

## What You Can Write NOW vs. What Needs Results

---

## ✅ CAN WRITE NOW (≈75% of the paper)

### I. Introduction — ✅ FULLY WRITABLE
Everything here is motivation and literature context, no results needed.

**Key points to cover:**
- Alert fatigue statistics (cite: "developers spend 25-35% of triage time on false positives" — Christakis & Bird, ICSE 2016)
- SAST adoption barrier: high FP rates cause "alarm fatigue" leading teams to ignore real vulnerabilities
- Gap: existing LLM approaches (IRIS, VulnLLMEval) operate on isolated code snippets — they can't reason about cross-file mitigations like middleware, reverse proxies, or config-level security controls
- Your contribution: a 3-phase pipeline that uses RAG to bridge this gap

**Contributions (bullet list):**
1. A multi-stage architecture that separates high-recall scanning (Phase 1) from semantic verification (Phase 3)
2. A CWE-aware RAG retrieval strategy that queries repository context for specific mitigation patterns
3. A strict-neutral verification prompt that eliminates common LLM biases (test-file mitigations, assumed-but-unseen controls)
4. Empirical evaluation on OWASP benchmarks demonstrating [X]% FP reduction

---

### II. Background and Motivation — ✅ FULLY WRITABLE
This is all literature review and problem motivation.

#### II.A. Limitations of Deterministic Taint Analysis
- Explain how SAST tools (Semgrep, CodeQL, Fortify) work: pattern matching on ASTs, taint tracking on data-flow graphs
- Key limitation: **localized scope** — they analyze individual files or function-level data flows
- They can't see: WAF rules, reverse proxy configs, middleware sanitizers in other files, security headers
- Result: over-reporting → high FP rates (typically 30-70% in literature)
- Cite: Semgrep docs, NIST SATE reports, Chess & West "Secure Programming with Static Analysis"

#### II.B. Limitations of LLM-Based Vulnerability Analysis
- Recent work: IRIS (NDSS 2025), VulnLLMEval, ChatGPT-based triage
- What they do well: understand code semantics better than regex/AST matching
- Key limitation: **context window bottleneck** — they receive a code snippet (50-200 lines), not the full repo
- They miss: cross-file sanitizers, configuration-level mitigations, architectural security patterns
- Example: An LLM seeing `eval(userInput)` in isolation calls it vulnerable, but if a middleware in another file strips dangerous characters, it's mitigated
- Cite: IRIS paper, any LLM-for-security survey papers

---

### III. Problem Formulation — ✅ FULLY WRITABLE
This is mathematical/conceptual framing.

#### III.A. Vulnerability Detection as Graph Analysis
Write this as formal notation:
- Define: Source nodes S = {user inputs}, Sink nodes K = {dangerous APIs}
- A vulnerability exists iff ∃ path P: s → k where s ∈ S, k ∈ K, and P passes through NO sanitizer node
- SAST tools find candidate paths P̂ but cannot verify sanitizer coverage → false positives
- Formalize: FP = {p ∈ P̂ | ∃ sanitizer(p) that SAST cannot observe}

#### III.B. Need for Repository-Level Context
- Argument: sanitizers exist at multiple architectural layers:
  1. **Inline** (same function) — SAST catches these
  2. **Same-file** (middleware in same module) — SAST sometimes catches
  3. **Cross-file** (separate middleware, config files) — SAST misses
  4. **Infrastructure** (WAF, reverse proxy, network policies) — SAST always misses
- Your system targets layers 2-3 via RAG retrieval across the full repository

---

### IV. Proposed Methodology — ✅ FULLY WRITABLE
This is your system design — you already built it, so describe it.

#### IV.A. System Architecture
- Draw a diagram showing: Repo → Phase 1 (Semgrep) → Phase 2 (Dedup/Filter) → Phase 3 (RAG Verifier) → Results
- Describe the data flow between phases

#### IV.B. Phase 1: High-Recall Deterministic Scanning
- Tool: Semgrep OSS with `--config auto`
- Output: raw JSON alerts with CWE labels, file paths, severity, confidence
- Design decision: use ALL rules (not filtered) to maximize recall
- Parse into structured format: (file, line, CWE, vulnerability_class, message)

#### IV.C. Phase 2: Syntax-Aware Filtering
- Purpose: lightweight deduplication and malformed-data removal
- NOT aggressive filtering — preserves all potentially valid findings
- Location-based deduplication: unique key = (file, line, vuln_type)
- Removes only: entries missing file path, CWE, or vulnerability type

#### IV.D. Phase 3: Repository-Level Context Verification
**This is your main contribution — describe in detail:**

1. **Semantic Chunking**: Repository code split into 1000-char chunks with 200-char overlap using RecursiveCharacterTextSplitter
2. **Vector Store**: HuggingFace `all-MiniLM-L6-v2` embeddings → ChromaDB
3. **CWE-Aware Retrieval**: Instead of generic keyword search, use a CWE → mitigation pattern lookup:
   - CWE-89 (SQLi) → search for "parameterized query", "prepared statement", "bind", "sequelize replacement"
   - CWE-79 (XSS) → search for "DOMPurify", "sanitize-html", "escapeHtml", "Content-Security-Policy"
   - CWE-798 (Hardcoded Secrets) → search for "process.env", "vault", "key rotation"
   - etc.
4. **Strict-Neutral Prompt Engineering**: 7 anti-hallucination rules:
   - Test files (.spec.*) are NOT mitigations
   - If you can't SEE the mitigation code, it doesn't exist
   - String truncation ≠ SQLi mitigation
   - localStorage ≠ secrets mitigation
   - Only parameterized queries count for CWE-89
   - Incomplete/bypassable mitigations → VALIDATED
   - When in doubt → VALIDATED (not MITIGATED)
5. **LLM Verification**: llama-3.3-70b-versatile via Groq API, temperature=0.0 for deterministic output

---

### V.A. Experimental Setup — ✅ PARTIALLY WRITABLE
You can write:
- Dataset description (OWASP Juice Shop: intentionally vulnerable Node.js/TypeScript application, ~100 documented challenges across 14 CWE categories)
- Ground truth methodology (manually cross-referenced Semgrep output against official challenge documentation)
- Tool versions (Semgrep 1.160.0, llama-3.3-70b-versatile, ChromaDB, etc.)
- Hardware/environment specs

### V.B. Evaluation Metrics — ✅ FULLY WRITABLE
Define your metrics:
- **Precision** = TP / (TP + FP) — "of what the system flags, how many are real?"
- **Recall** = TP / (TP + FN) — "of real vulnerabilities, how many did we find?"
- **False Discovery Rate (FDR)** = FP / (FP + TP)
- **FP Reduction Rate** = (FP_phase1 - FP_phase3) / FP_phase1

---

### VI. Discussion and Limitations — ✅ MOSTLY WRITABLE
You already know the limitations:
- **Computational overhead**: RAG retrieval + LLM inference adds ~12s per finding
- **Rate limiting**: Cloud LLM APIs impose token limits (100k TPD for 70b models)
- **Embedding quality**: MiniLM-L6-v2 may miss semantic connections for domain-specific security patterns
- **Retrieval precision**: ChromaDB top-k retrieval may return irrelevant chunks if the repo is large
- **Single-language evaluation**: Current evaluation is on TypeScript/JavaScript only
- **LLM hallucination risk**: Despite strict prompts, LLMs can still fabricate mitigation evidence

---

### VII. Conclusion — ✅ PARTIALLY WRITABLE
Write the structure, leave blanks for numbers:
- "Our system reduced false positives by [X]% while maintaining [Y]% recall"
- Future work: multi-language evaluation, fine-tuned security-specific embeddings, integration with CI/CD pipelines

---

## ❌ CANNOT WRITE YET (needs results)

| Section | What's Missing | When You Can Write It |
|---|---|---|
| **Abstract** (final numbers) | The [X]%, [Y]%, [Z]% placeholders | After running Phase 3 |
| **V.C. Results and Analysis** | The actual precision/recall/F1 table | After running Phase 3 |
| **V.D. Case Study** | A specific example where RAG correctly filtered a FP | After running Phase 3 |
| **V.E. Ablation Study** | Comparing with/without Phase 2, different k values | After running Phase 3 variations |
| **VII. Conclusion** (final sentences) | Summary numbers | After all results |

---

## Recommended Writing Order

```
Week 1 (NOW — no results needed):
├── III. Problem Formulation          (2-3 pages)
├── IV. Proposed Methodology          (4-5 pages, your main contribution)
├── II. Background and Motivation     (2-3 pages)
├── V.A. Experimental Setup           (1 page)
├── V.B. Evaluation Metrics           (0.5 page)
└── VI. Discussion and Limitations    (1-2 pages)

Week 2 (after running experiments):
├── V.C. Results and Analysis         (2 pages)
├── V.D. Case Study                   (1 page)
├── V.E. Ablation Study              (1 page)
├── I. Introduction (finalize)        (1.5 pages)
├── Abstract (finalize)               (0.5 page)
└── VII. Conclusion (finalize)        (0.5 page)
```

---

## Key References to Cite

| Paper/Tool | What to Cite For |
|---|---|
| IRIS (NDSS 2025) | LLM-based vulnerability detection, localized analysis limitation |
| Semgrep (r2c) | Deterministic SAST, pattern-based scanning |
| Christakis & Bird (ICSE 2016) | Developer perception of static analysis, false positive burden |
| NIST SATE Reports | SAST tool evaluation benchmarks |
| Lewis et al. (2020) — RAG paper | Retrieval-Augmented Generation concept |
| OWASP Juice Shop documentation | Ground truth for evaluation |
| Chess & West — "Secure Programming with Static Analysis" | SAST fundamentals |
| CWE/MITRE database | Vulnerability classification |

---

## Title Feedback

Your title is strong:
> "A Multi-Stage LLM Verifier for Reducing Static Analysis False Positives via Repository-Level Semantic Verification"

Suggestion — slightly shorter alternative:
> "Repository-Level Semantic Verification: A Multi-Stage LLM Framework for SAST False Positive Reduction"

Both work. The key selling phrase is **"repository-level"** — that's your differentiator from IRIS and other localized approaches.

## Abstract Feedback

Your abstract is well-written. Two suggestions:
1. Replace "cloud-native microservices" with actual dataset names (WebGoat, NodeGoat) once you decide
2. Add one sentence about the CWE-aware retrieval strategy — it's your novel contribution and should appear in the abstract

---

## One Dataset Framing

Since you asked — if you only use Juice Shop, change:
- Title: add "A Case Study" or "An Empirical Study"
- Abstract: "Evaluated on the OWASP Juice Shop benchmark" (not "diverse benchmarks")
- Add explicit limitation: "Our evaluation is limited to a single benchmark application; generalization to production codebases requires further study"
