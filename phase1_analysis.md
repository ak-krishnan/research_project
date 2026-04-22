# Phase 1 Analysis: Semgrep Findings vs Ground Truth

Cross-referencing the **38 Semgrep findings** from `phase1.md` against the **official Juice Shop challenge documentation** (`documentation.md`).

---

## Summary Metrics

| Metric | Count |
|---|---|
| **Total Semgrep Findings** | 38 |
| **Duplicates** (same location, different rules) | 2 |
| **Unique Findings** | 36 |
| **True Positives** | 29 |
| **False Positives** | 7 |
| **Precision** | **80.6%** |
| **False Positive Rate** | **19.4%** |

---

## Detailed Finding-by-Finding Classification

### ✅ TRUE POSITIVES (29 findings — map to documented vulnerabilities)

| # | File | CWE | Vuln Type | Maps to Challenge(s) | Rationale |
|---|---|---|---|---|---|
| 1 | `codefixes/dbSchemaChallenge_1.ts` | CWE-89 | SQL Injection | `dbSchemaChallenge` | Raw SQL query with user input concatenation. Intentionally vulnerable codefix variant. |
| 2 | `codefixes/dbSchemaChallenge_3.ts` | CWE-89 | SQL Injection | `dbSchemaChallenge` | Same vulnerability, different codefix variant. Has regex check but it's bypassable. |
| 3 | `codefixes/restfulXssChallenge_2.ts` | CWE-79 | XSS (replaceAll) | `restfulXssChallenge` | Manual sanitization via `replaceAll()` is incomplete — well-documented as insufficient. |
| 5 | `codefixes/unionSqlInjectionChallenge_1.ts` | CWE-89 | SQL Injection | `unionSqlInjectionChallenge` | Raw SQL with string interpolation of `req.query.q`. |
| 6 | `codefixes/unionSqlInjectionChallenge_3.ts` | CWE-89 | SQL Injection | `unionSqlInjectionChallenge` | Same challenge, codefix variant with partial mitigation. |
| 7 | `data/static/users.yml` | CWE-798 | Hardcoded Secrets | `exposedCredentialsChallenge`, `loginSupportChallenge` | TOTP secrets and user data in a YAML file. Intentionally planted. |
| 11 | `frontend/.../helpers.ts` | CWE-915 | Prototype Pollution | `registerAdminChallenge` (Mass Assignment) | Dynamic property access in a loop can modify object prototype. |
| 14 | `lib/insecurity.ts` (line 44) | CWE-798 | Hardcoded HMAC Key | `weirdCryptoChallenge`, `continueCodeChallenge` | `hmac()` function uses hardcoded key `pa4qacea4VK9t9nGv7yZtwmj`. |
| 15 | `lib/insecurity.ts` (line 56) | CWE-798 | Hardcoded JWT Secret | `jwtUnsignedChallenge`, `jwtForgedChallenge` | JWT signing with hardcoded secret string. Core JWT challenge. |
| 16 | `lib/insecurity.ts` (line 152) | CWE-798 | Hardcoded HMAC Key | `weirdCryptoChallenge` | Second hardcoded HMAC usage in the same file. |
| 17 | `routes/b2bOrder.ts` | CWE-1104 | Unmaintained Component (notevil) | `rceChallenge`, `rceOccupyChallenge` | Uses `notevil` package for `eval()`-like execution of user input — RCE vector. |
| 19 | `routes/chatbot.ts` | CWE-79 | XSS (raw HTML) | `httpHeaderXssChallenge` | User-controlled data interpolated into raw HTML without sanitization. |
| 20 | `routes/currentUser.ts` | CWE-522 | Property Injection | `passwordHashLeakChallenge` | Bracket notation `user[key]` with user-controlled key exposes all properties including password hash. |
| 21 | `routes/fileServer.ts` | CWE-73 | Path Traversal | `directoryListingChallenge`, `forgottenDevBackupChallenge`, `forgottenBackupChallenge`, `nullByteChallenge` | `res.sendFile()` with user-controlled path. Core file access vulnerability. |
| 22 | `routes/fileUpload.ts` | CWE-611 | XXE | `xxeFileDisclosureChallenge`, `xxeDosChallenge`, `deprecatedInterfaceChallenge` | `parseXml()` with `noent: true` — classic XXE configuration. |
| 23 | `routes/keyServer.ts` | CWE-73 | Path Traversal | `easterEggLevelOneChallenge`, `misplacedSignatureFileChallenge` | `res.sendFile()` with user input. Has simple slash check that can be bypassed (null byte). |
| 24 | `routes/logfileServer.ts` | CWE-73 | Path Traversal | `accessLogDisclosureChallenge` | `res.sendFile()` with user input, same pattern as above. |
| 25 | `routes/login.ts` | CWE-89 | SQL Injection | `loginAdminChallenge`, `loginBenderChallenge`, `loginJimChallenge`, `ephemeralAccountantChallenge` | **The** core SQL injection — `sequelize.query()` with string interpolation of `req.body.email`. |
| 26 | `routes/quarantineServer.ts` | CWE-73 | Path Traversal | `sstiChallenge` | `res.sendFile()` with user input, access to quarantine folder. |
| 27 | `routes/redirect.ts` | CWE-601 | Open Redirect | `redirectCryptoCurrencyChallenge`, `redirectChallenge` | Redirect to user-controlled URL. Allowlist exists but is bypassable. |
| 28 | `routes/search.ts` | CWE-89 | SQL Injection | `christmasSpecialChallenge`, `dbSchemaChallenge` | `sequelize.query()` with string interpolation of search query. |
| 29 | `routes/userProfile.ts` | CWE-95 | Eval Injection | `usernameXssChallenge` | `eval()` on user-controlled template data — code injection via username. |
| 31 | `routes/videoHandler.ts` (line 58) | CWE-79 | XSS (script tag) | `videoXssChallenge` | `subs` variable used inside `<script>` tag without sanitization. |
| 32 | `routes/videoHandler.ts` (line 71) | CWE-79 | XSS (script tag) | `videoXssChallenge` | Same vulnerability, different code path in the same handler. |
| 34 | `server.ts` (line 269) | CWE-548 | Directory Listing | `directoryListingChallenge` | `serve-index` middleware enables directory browsing on `/ftp`. |
| 35 | `server.ts` (line 273) | CWE-548 | Directory Listing | `directoryListingChallenge` | Directory listing on another path. |
| 36 | `server.ts` (line 277) | CWE-548 | Directory Listing | `directoryListingChallenge` | Directory listing on yet another path. |
| 37 | `server.ts` (line 281) | CWE-548 | Directory Listing | `directoryListingChallenge` | Directory listing on yet another path. |
| 38 | `views/promotionVideo.pug` | CWE-79 | XSS (Pug unescape) | `videoXssChallenge` | Explicit unescape `!=` in Pug template allows XSS via subtitle injection. |

---

### ❌ FALSE POSITIVES (7 findings — not actual exploitable vulnerabilities)

| # | File | CWE | Vuln Type | Why False Positive |
|---|---|---|---|---|
| 8 | `frontend/.../app.guard.spec.ts` | CWE-321 | JWT Token | **Test file** (`.spec.ts`). JWT token is a mock for unit testing, not a real credential in production code. |
| 9 | `frontend/.../last-login-ip.component.spec.ts` (line 61) | CWE-321 | JWT Token | **Test file** (`.spec.ts`). Mock JWT for testing the last-login-IP display component. |
| 10 | `frontend/.../last-login-ip.component.spec.ts` (line 67) | CWE-321 | JWT Token | **Test file** (`.spec.ts`). Same file, another mock JWT on a different line. |
| 12 | `lib/codingChallenges.ts` (line 76) | CWE-1333 | ReDoS | `challengeKey` comes from **internal config/file system**, NOT from user input. No attack surface for ReDoS. |
| 13 | `lib/codingChallenges.ts` (line 78) | CWE-1333 | ReDoS | Same as above — non-literal RegExp on server-controlled data, not user-controlled. |
| 18 | `routes/captcha.ts` | CWE-95 | Eval Injection | `eval()` is used on **randomly generated math expressions** (e.g., `eval("7+3")`), NOT on user input. The CAPTCHA answer is validated, not evaluated. |
| 33 | `server.ts` (line 155) | CWE-134 | Format String | `console.log()` with string concatenation. Severity is `INFO`, impact is negligible — this is a logging statement, not a user-facing output. No practical exploit path. |

---

### 🔁 DUPLICATES (2 findings — same location, different Semgrep rules)

| # | File | CWE | Duplicate Of | Reason |
|---|---|---|---|---|
| 4 | `codefixes/restfulXssChallenge_2.ts` (line 49) | CWE-79 | Finding #3 | Same line, overlapping column range. Two `replaceAll()` calls chained — Semgrep fires on both the inner and outer call. |
| 30 | `routes/userProfile.ts` (line 62) | CWE-95 | Finding #29 | Exact same location (line 62). Rule `code-string-concat` detects same `eval()` that `eval-detected` already found. |

---

## False Positive Breakdown by Category

| FP Category | Count | Examples |
|---|---|---|
| **Test files** (`.spec.ts`) | 3 | JWT tokens in unit test mocks |
| **Non-user-controlled input** | 2 | RegExp on server-controlled `challengeKey` |
| **Benign eval usage** | 1 | `eval()` on auto-generated math expressions |
| **Informational / No exploit path** | 1 | Format string in `console.log()` |

---

## What Semgrep MISSED (in documentation.md but not in Phase 1)

The documentation lists **~100 challenges**. Semgrep found vulnerabilities related to **~25 of them**. The ~75 missed challenges fall into categories that SAST tools inherently cannot detect:

| Category | Why SAST Misses It | Example Challenges |
|---|---|---|
| **Business Logic Flaws** | No pattern to match | Basket Manipulation, Payback Time, Deluxe Fraud |
| **Broken Authentication** | Requires runtime context | Change Bender's Password, GDPR Data Erasure, Two Factor Auth |
| **OSINT / Social Engineering** | External to codebase | Reset Jim's Password, Bjoern's Favorite Pet, Login Amy |
| **Broken Access Control** (authz) | Requires semantic understanding | Admin Section, View Basket, Forged Feedback |
| **Cryptographic Issues** | Logic-level, not pattern | Forged Coupon, Nested Easter Egg, Imaginary Challenge |
| **NoSQL Injection** | Semgrep JS rules don't cover MongoDB `$where` | NoSQL DoS, NoSQL Exfiltration, NoSQL Manipulation |
| **Insecure Deserialization** | Complex multi-step exploits | Blocked RCE DoS, Memory Bomb |
| **Web3 / Blockchain** | Domain-specific, no rules | NFT Takeover, Wallet Depletion |

> [!IMPORTANT]
> This is expected behavior for SAST tools. Semgrep excels at **pattern-matching** (SQLi, XSS, path traversal, hardcoded secrets) but cannot detect **logic flaws**, **authorization issues**, or vulnerabilities requiring **runtime context**. This is precisely why the RAG-augmented Phase 3 verification layer exists — to provide contextual triage of what Semgrep CAN detect.

---

## Key Takeaways for Research Paper

1. **Semgrep Precision = 80.6%** — This means ~1 in 5 findings is a false positive, which is a significant burden for human reviewers.
2. **Most FPs have clear patterns**: test files (3/7), non-user-controlled input (2/7), benign operations (2/7). These are exactly what RAG-augmented triage should filter.
3. **Semgrep Recall is inherently limited** to pattern-matchable vulnerability classes. It found ~25/100 challenges, which is consistent with SAST limitations.
4. **The 7 FPs are the target** for your RAG Phase 3 to correctly classify as `MITIGATED` or `FALSE_POSITIVE`, while keeping the 29 TPs as `VALIDATED`.
