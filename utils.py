import os
import re
import json
import uuid
import tempfile
import time
from git import Repo

from langchain_community.document_loaders import TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter, Language
from langchain_community.vectorstores import FAISS
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_openai import ChatOpenAI
from langchain_classic.chains import RetrievalQA
from langchain_core.prompts import PromptTemplate
from langchain_core.messages import HumanMessage, SystemMessage
import subprocess


def clone_repo(url):
    path = tempfile.mkdtemp()
    Repo.clone_from(url, path)
    return path

def load_documents(path):
    docs = []
    allowed_ext = (
        ".py", ".js", ".ts", ".jsx", ".tsx",
        ".html", ".css", ".scss", ".md",
        ".json", ".java", ".cpp", ".c", ".go",
        ".rs", ".php", ".rb", ".sh", ".yml", ".yaml"
    )
    ignored_dirs = {
        ".git", "node_modules", "venv", "__pycache__",
        ".next", "dist", "build", ".idea", ".vscode",
        "codefixes"
    }

    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in ignored_dirs]
        for file in files:
            if file.endswith(".info.yml"):
                continue
            if file.endswith(allowed_ext):
                file_path = os.path.join(root, file)
                try:
                    loader = TextLoader(file_path, encoding="utf-8")
                    docs.extend(loader.load())
                except:
                    pass
    return docs

def split_docs(docs):
    chunks = []
    default_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=100)
    ext_to_lang = {
        ".py": Language.PYTHON, ".js": Language.JS, ".ts": Language.TS,
        ".jsx": Language.JS, ".tsx": Language.TS, ".html": Language.HTML,
        ".md": Language.MARKDOWN, ".java": Language.JAVA, ".cpp": Language.CPP,
        ".c": Language.CPP, ".go": Language.GO, ".rs": Language.RUST,
        ".php": Language.PHP, ".rb": Language.RUBY,
    }

    for doc in docs:
        source = doc.metadata.get("source", "")
        ext = os.path.splitext(source)[1].lower()
        if ext in ext_to_lang:
            splitter = RecursiveCharacterTextSplitter.from_language(
                language=ext_to_lang[ext], chunk_size=1000, chunk_overlap=100
            )
            chunks.extend(splitter.split_documents([doc]))
        else:
            chunks.extend(default_splitter.split_documents([doc]))
            
    return chunks

def create_vectorstore(chunks):
    emb = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
    vectordb = FAISS.from_documents(chunks, emb)
    return vectordb, None

def create_qa_chain(vectordb, groq_key, file_tree, security_mode=False):
    llm = ChatOpenAI(
        model="llama-3.1-8b-instant",
        api_key=groq_key,
        base_url="https://api.groq.com/openai/v1",
        temperature=0.0 if security_mode else 0.2
    )

    if security_mode:
        prompt_template = f"""
You are an automated Static Application Security Testing (SAST) framework and a strict Cybersecurity Engineer.
Your ONLY objective is to analyze the provided code context and detect OWASP Top 10 vulnerabilities.

Here is the overall architecture of the repository:
{file_tree}

CRITICAL RULES:
1. You must ONLY output identified vulnerabilities that are EXPLICITLY FOUND in the provided Context.
2. DO NOT hallucinate. DO NOT assume vulnerabilities exist in files you cannot see. If a vulnerability is "not shown in the snippet", you MUST NOT report it. 
3. No conversational filler, greetings, or conclusions.
4. If no vulnerabilities are clearly found in the specific context provided, output exactly: "No obvious OWASP vulnerabilities detected in the current context."
5. If vulnerabilities ARE found, you MUST use the exact format below. You MUST include double line breaks between each field so it renders correctly in Markdown:

**Vulnerability Name:** [Name of the vulnerability]

**CWE ID:** [e.g., CWE-89]

**Severity:** [Critical, High, Medium, or Low]

**Line Context:** [Filename and exact code snippet]

**Fix:** [A precise, 1-sentence instruction to remediate the issue]

---

Do not deviate from this format. 

Question: {{question}}
Context: {{context}}

Answer:
"""
    else:
        prompt_template = f"""
You are RepoMind, an expert software engineer and repository analyst.
Answer ONLY using the repository context provided below.
If the answer is not clearly available in the context, say: "I could not confidently find that in the repository."

Here is the overall architecture of the repository:
{file_tree}

Rules:
- Be specific and practical.
- Mention filenames when relevant.
- Do NOT guess or hallucinate.
- Keep answers clear and structured.

Question: {{question}}
Context: {{context}}

Answer:
"""

    PROMPT = PromptTemplate(template=prompt_template, input_variables=["context", "question"])

    return RetrievalQA.from_chain_type(
        llm=llm,
        retriever=vectordb.as_retriever(search_kwargs={"k": 10}),
        chain_type="stuff",
        return_source_documents=True,
        chain_type_kwargs={"prompt": PROMPT}
    )

def get_file_tree(path):
    tree = ""
    ignored_dirs = {".git", "node_modules", "venv", "__pycache__", ".next", "dist", "build", ".idea", ".vscode"}
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in ignored_dirs]
        level = root.replace(path, "").count(os.sep)
        indent = "  " * level
        folder_name = os.path.basename(root) if os.path.basename(root) else "repo"
        tree += f"{indent}{folder_name}/\n"
        for f in files:
            tree += f"{indent}  {f}\n"
    return tree

def detect_project_type(path):
    files = set()
    for root, _, filenames in os.walk(path):
        for f in filenames:
            files.add(f.lower())

    if "package.json" in files:
        if "vite.config.js" in files or "vite.config.ts" in files: return "Vite / JavaScript or React Project"
        if "next.config.js" in files: return "Next.js Project"
        return "JavaScript / Node.js Project"
    if "requirements.txt" in files or "app.py" in files: return "Python Project"
    if "pom.xml" in files: return "Java / Maven Project"
    if "cargo.toml" in files: return "Rust Project"
    if "go.mod" in files: return "Go Project"
    return "Unknown / Mixed Tech Project"

def extract_dependencies(path):
    deps = []
    
    package_json = os.path.join(path, "package.json")
    if os.path.exists(package_json):
        try:
            with open(package_json, "r", encoding="utf-8") as f:
                data = json.load(f)
                for section in ["dependencies", "devDependencies"]:
                    if section in data: deps.extend(list(data[section].keys()))
        except: pass

    requirements = os.path.join(path, "requirements.txt")
    if os.path.exists(requirements):
        try:
            with open(requirements, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"): deps.append(line)
        except: pass

    pom = os.path.join(path, "pom.xml")
    if os.path.exists(pom):
        try:
            with open(pom, "r", encoding="utf-8") as f:
                matches = re.findall(r"<artifactId>(.*?)</artifactId>", f.read())
                deps.extend(matches)
        except: pass

    return sorted(list(set(deps)))


# -------------------------
# Deterministic Scanner (Phase 1) — Multi-Config Support
# -------------------------
def run_semgrep(repo_path, config="p/default", exclude_patterns=None):
    """
    Runs Semgrep CLI. 
    Forces local rules and completely disables telemetry to prevent opentelemetry crashes.
    Supports exclude patterns to filter out noise files.
    """
    try:
        semgrep_path = "semgrep"
        command = [
            semgrep_path, "scan", 
            "--config=" + config, 
            "--json", 
            "--quiet", 
            repo_path
        ]
        
        # Add exclude patterns to skip codefix variants, test files, i18n, etc.
        if exclude_patterns:
            for pattern in exclude_patterns:
                command.insert(-1, f"--exclude={pattern}")
        
        # Clone the current OS environment and inject the kill-switch
        custom_env = os.environ.copy()
        
        # NEW: Semgrep config=auto REQUIRES metrics to be on to generate the config.
        if config == "auto":
            custom_env["SEMGREP_SEND_METRICS"] = "on"
            custom_env["SEMGREP_ENABLE_METRICS"] = "on"
        else:
            custom_env["SEMGREP_SEND_METRICS"] = "off"
            custom_env["SEMGREP_ENABLE_METRICS"] = "off"
        
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            env=custom_env # Pass the modified environment
        )
        
        if result.stdout:
            return json.loads(result.stdout)
        else:
            return {"error": "Semgrep executed but returned no output.", "stderr": result.stderr}
            
    except Exception as e:
        return {"error": f"An unexpected execution error occurred: {str(e)}"}


def run_semgrep_multi(repo_path, configs=None, exclude_patterns=None):
    """
    Runs Semgrep with MULTIPLE configs and merges all results.
    This catches more vulnerability types than a single config.
    """
    if configs is None:
        configs = ["auto"]
    
    all_results = []
    
    for config in configs:
        print(f"  Running Semgrep with config: {config}...")
        raw = run_semgrep(repo_path, config=config, exclude_patterns=exclude_patterns)
        
        if "error" not in raw:
            results = raw.get("results", [])
            all_results.extend(results)
            print(f"    -> Found {len(results)} findings with {config}")
        else:
            print(f"    -> Error with {config}: {raw.get('error', 'Unknown')}")
    
    # Merge into a single raw JSON structure
    return {"results": all_results}


# -------------------------
# Segment 2: Parser & Snippet Extractor — With Deduplication
# -------------------------
def is_noise_file(file_path):
    """Filter out test files, mocks, i18n, and variant directories."""
    noise_patterns = [
        r'/test/', r'/tests/', r'/testing/',
        r'/mock/', r'/mocks/',
        r'/i18n/', r'/locales/', r'/translations/',
        r'/codefix/', r'/variant/',
        r'Test\.java$', r'Mock.*\.java$', r'.*Fixture.*\.java$',
        r'.*IntegrationTest.*\.java$', r'.*UnitTest.*\.java$',
    ]
    for pattern in noise_patterns:
        if re.search(pattern, file_path, re.IGNORECASE):
            return True
    return False

def is_allowed_for_rule(rule_short, file_name):
    """Per-rule filtering for high false-positive patterns."""
    # Rules prone to false positives in certain contexts
    fp_prone_rules = {
        'java.lang.security': {  # Hardcoded secrets/credentials
            'exclude_in': ['.properties', '.json', '.config', '.yaml', 'application.yml']
        },
        'java.sql.injection': {
            'exclude_in': ['Entity.java', 'Model.java']  # ORM classes often false positives
        },
        'java.crypto': {
            'exclude_in': ['Test', 'Config']  # Crypto configs in test/config files
        }
    }

    # Check if this rule has known FP contexts
    for fp_rule, contexts in fp_prone_rules.items():
        if fp_rule in rule_short:
            for exclude_pattern in contexts.get('exclude_in', []):
                if exclude_pattern in file_name:
                    return False  # Filter out this finding
    return True

def classify_finding(alert, repo_context=""):
    """Lightweight purification: only discard completely malformed/empty findings.
    All real vulnerability decisions are deferred to Phase 3.
    Returns: {"decision": str, "reason": str, "confidence": str}
    """
    file_name = alert.get('file', '')
    check_id = alert.get('vulnerability', '')
    code_snippet = alert.get('code_snippet', '')

    # Rule 1: Discard completely malformed findings (no file or no rule ID)
    if not file_name or not check_id:
        return {
            "decision": "DISCARD_NOISE",
            "reason": "Malformed finding: missing file name or check ID",
            "confidence": "HIGH"
        }

    # Rule 2: Discard findings where snippet extraction completely failed
    if code_snippet and code_snippet.startswith("Could not extract snippet:"):
        return {
            "decision": "DISCARD_NOISE",
            "reason": f"Could not read source file for {file_name}",
            "confidence": "HIGH"
        }

    # Default: Pass everything else to Phase 3 for real verification
    return {
        "decision": "PASS",
        "reason": "Forwarded to Phase 3 for context-aware verification",
        "confidence": "MEDIUM"
    }


def get_code_snippet(file_path, line_number, context_lines=7):
    """Reads the file and grabs the vulnerable line plus surrounding context.
    Increased context_lines from 5 to 7 for better analysis."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            
        start_idx = max(0, line_number - 1 - context_lines)
        end_idx = min(len(lines), line_number + context_lines)
        
        snippet = "".join(lines[start_idx:end_idx])
        return snippet
    except Exception as e:
        return f"Could not extract snippet: {e}"

def parse_semgrep_output(raw_json):
    """Pure data extractor: parses ALL Semgrep results without filtering.
    No findings are dropped here — all filtering decisions are deferred to Phase 2/3."""
    
    # Catch execution errors
    if "error" in raw_json:
        return [{
            "vulnerability": "Execution Error", 
            "message": f"Semgrep failed: {raw_json.get('error')} | STDERR: {raw_json.get('stderr', '')}", 
            "file": "System", 
            "cwe": "N/A"
        }]

    parsed_alerts = []
    results = raw_json.get("results", [])
    
    for r in results:
        file_path = r.get("path", "")
        file_name = os.path.basename(file_path)
        line_num = r.get("start", {}).get("line", 0)
        check_id = r.get("check_id", "")
        
        alert = {
            "file": file_name,
            "full_path": file_path,
            "line": line_num,
            "vulnerability": check_id,
            "message": r.get("extra", {}).get("message", ""),
            "cwe": _extract_cwe(r.get("extra", {}).get("metadata", {})),
            "severity": r.get("extra", {}).get("severity", "WARNING"),
            "code_snippet": get_code_snippet(file_path, line_num),
            "owasp_category": _map_to_owasp(check_id, r.get("extra", {}).get("metadata", {}))
        }
        parsed_alerts.append(alert)

    return parsed_alerts


def _extract_cwe(metadata):
    """Extract CWE ID from metadata, handling both list and string formats."""
    cwe_data = metadata.get("cwe", "Unknown")
    if isinstance(cwe_data, list):
        if cwe_data:
            # Extract number from string like "CWE-89: ..."
            cwe_str = cwe_data[0]
            cwe_num = cwe_str.split(':')[0].replace('CWE-', '') if 'CWE-' in cwe_str else cwe_str
            return cwe_num
        return "Unknown"
    elif isinstance(cwe_data, str):
        if 'CWE-' in cwe_data:
            return cwe_data.split('CWE-')[1].split(':')[0]
        return cwe_data
    return "Unknown"


def deduplicate_findings(parsed_alerts):
    """Location-based deduplication: only removes exact duplicates
    (same vulnerability at the same file and line number).

    Every unique vulnerability location is preserved for Phase 3 verification.
    """
    if not parsed_alerts:
        return []

    # Group by exact location: (vulnerability_type, file, line)
    seen = {}
    deduplicated = []
    duplicate_count = 0

    for alert in parsed_alerts:
        key = (
            alert.get('vulnerability', ''),
            alert.get('file', ''),
            alert.get('line', 0)
        )
        if key not in seen:
            seen[key] = alert
            deduplicated.append(alert)
        else:
            duplicate_count += 1

    # Add overall dedup stats to the first finding for reporting
    if deduplicated and duplicate_count > 0:
        deduplicated[0]['total_exact_duplicates_removed'] = duplicate_count

    return deduplicated


def _map_to_owasp(check_id, metadata):
    """Map a Semgrep check ID to the user's 16 specific categories."""
    check_lower = check_id.lower()
    
    # Injection categories
    if "sqli" in check_lower or "sequelize-injection" in check_lower:
        return "Injection"
    elif "xss" in check_lower or "sanitiz" in check_lower:
        return "XSS"
    elif "xxe" in check_lower or "libxml" in check_lower:
        return "XXE"
    elif "eval" in check_lower or "code-string" in check_lower:
        return "Injection"
    
    # Authentication & Authorization
    elif "broken-auth" in check_lower or "jwt" in check_lower or "login" in check_lower:
        return "Broken Authentication"
    elif "broken-access" in check_lower or "idore" in check_lower or "access-control" in check_lower:
        return "Broken Access Control"
    elif "redirect" in check_lower:
        return "Unvalidated Redirects"
    
    # Data & Crypto
    elif "sensitive-data" in check_lower or "exposure" in check_lower:
        return "Sensitive Data Exposure"
    elif "crypto" in check_lower or "hash" in check_lower or "hardcoded-secret" in check_lower:
        return "Cryptographic Issues"
    
    # Validation & Deserialization
    elif "input-validation" in check_lower or "sanitization" in check_lower:
        return "Improper Input Validation"
    elif "deserialization" in check_lower or "yaml" in check_lower:
        return "Insecure Deserialization"
    
    # Components & Config
    elif "vulnerable-component" in check_lower or "zip-slip" in check_lower:
        return "Vulnerable Components"
    elif "misconfiguration" in check_lower:
        return "Security Misconfiguration"
    
    # Others
    elif "obscurity" in check_lower:
        return "Security through Obscurity"
    elif "observability" in check_lower or "logging" in check_lower:
        return "Observability Failures"
    elif "anti-automation" in check_lower or "captcha" in check_lower:
        return "Broken Anti Automation"
    
    return "Miscellaneous"


# -------------------------
# Segment 2: The Scout Agent — Phase 2 Lightweight Purification
# -------------------------
def run_scout_agent(parsed_alerts, groq_key):
    """Phase 2: Lightweight Purification.

    Only discards malformed/unreadable findings.
    All real vulnerability decisions are deferred to Phase 3 (Context Verifier).
    Returns findings that pass purification, with summary report.
    """
    if not parsed_alerts:
        return "No vulnerabilities detected by the deterministic scanner.", []

    # Phase 2: Lightweight purification
    passed_findings = []
    discarded_findings = []
    stats = {"total": len(parsed_alerts), "passed": 0, "discarded": 0}

    for alert in parsed_alerts:
        decision_obj = classify_finding(alert)

        if decision_obj["decision"] == "PASS":
            alert["phase_2_decision"] = "PASS"
            alert["phase_2_confidence"] = decision_obj["confidence"]
            passed_findings.append(alert)
            stats["passed"] += 1
        else:
            discarded_findings.append({**alert, **decision_obj})
            stats["discarded"] += 1

    # Report generation
    scout_report = f"""## 🕵️ Phase 2: Purification (Lightweight Triage)

**Summary:**
- Total Findings from Phase 1: {stats['total']}
- Forwarded to Phase 3: {stats['passed']} ({100*stats['passed']//max(stats['total'],1)}%)
- Discarded (malformed/unreadable): {stats['discarded']}

### Findings Forwarded to Phase 3 ({stats['passed']})
"""

    if passed_findings:
        for alert in passed_findings[:20]:  # Show first 20
            scout_report += f"\n- **{alert['vulnerability']}** in {alert['file']} (Line {alert['line']})"
        if len(passed_findings) > 20:
            scout_report += f"\n- ... and {len(passed_findings) - 20} more"

    if discarded_findings:
        scout_report += f"\n\n### Discarded ({stats['discarded']})\n"
        for finding in discarded_findings[:5]:
            scout_report += f"\n- {finding.get('reason', 'Unknown')}: {finding.get('file', 'N/A')}"

    return scout_report, passed_findings

# -------------------------
# Java-specific Utilities for Method-level Precision
# -------------------------
def extract_java_method_info(file_path, line_number):
    """
    For Java files, extract the method that contains the vulnerable line.
    Returns method signature and context.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        # Simple regex-based method detection
        import re
        method_pattern = r'(public|private|protected|static|final|synchronized)*\s+\w+\s+(\w+)\s*\([^)]*\)\s*\{'

        # Work backwards from the vulnerable line to find the containing method
        for i in range(line_number - 1, -1, -1):
            match = re.search(method_pattern, lines[i])
            if match:
                method_name = match.group(2) if match.group(2) else "Unknown"
                return method_name

        return "Unknown"
    except Exception as e:
        return "Unknown"


# -------------------------
# CWE-specific mitigation patterns for smarter RAG queries
# -------------------------
CWE_MITIGATION_PATTERNS = {
    # SQL Injection
    "89": {
        "code_patterns": ["PreparedStatement", "setString", "setInt", "parameterized", "createNamedQuery", "CriteriaBuilder", "@Param", "JdbcTemplate", "NamedParameterJdbcTemplate"],
        "query": "PreparedStatement parameterized query setString createNamedQuery"
    },
    # XSS
    "79": {
        "code_patterns": ["escapeHtml", "HtmlUtils.htmlEscape", "StringEscapeUtils", "encodeForHTML", "sanitize", "ContentSecurityPolicy", "X-XSS-Protection"],
        "query": "escapeHtml htmlEscape sanitize encodeForHTML output encoding"
    },
    # Path Traversal
    "22": {
        "code_patterns": ["normalize", "getCanonicalPath", "FilenameUtils", "validatePath", "Path.resolve", "startsWith"],
        "query": "getCanonicalPath normalize path validation FilenameUtils resolve"
    },
    # XXE
    "611": {
        "code_patterns": ["setFeature", "FEATURE_SECURE_PROCESSING", "disallow-doctype-decl", "XMLInputFactory", "IS_SUPPORTING_EXTERNAL_ENTITIES"],
        "query": "setFeature disallow-doctype-decl XMLInputFactory FEATURE_SECURE_PROCESSING"
    },
    # Deserialization
    "502": {
        "code_patterns": ["ObjectInputFilter", "resolveClass", "whitelist", "ValidatingObjectInputStream", "NotSerializableException"],
        "query": "ObjectInputFilter resolveClass whitelist ValidatingObjectInputStream deserialization"
    },
    # CSRF
    "352": {
        "code_patterns": ["csrf", "CsrfToken", "_csrf", "csrfProtection", "antiforgery", "SynchronizerToken"],
        "query": "csrf CsrfToken csrfProtection SynchronizerToken antiForgery"
    },
    # Command Injection
    "78": {
        "code_patterns": ["ProcessBuilder", "allowlist", "whitelist", "shlex", "escapeshell", "sanitize"],
        "query": "ProcessBuilder allowlist whitelist command sanitize validation"
    },
    # Insecure Crypto
    "327": {
        "code_patterns": ["AES", "GCM", "SHA-256", "SHA-512", "PBKDF2", "BCrypt", "Argon2"],
        "query": "AES GCM SHA-256 PBKDF2 BCrypt strong cipher algorithm"
    },
    # Hardcoded Credentials
    "798": {
        "code_patterns": ["getenv", "System.getProperty", "@Value", "ConfigurationProperties", "vault", "secretsmanager"],
        "query": "getenv getProperty ConfigurationProperties vault secrets externalized"
    },
    # Open Redirect
    "601": {
        "code_patterns": ["allowlist", "whitelist", "validateRedirectUrl", "isSafeUrl", "startsWith"],
        "query": "redirect allowlist whitelist validateUrl isSafeUrl domain check"
    },
    # SSRF
    "918": {
        "code_patterns": ["allowlist", "whitelist", "isPrivateAddress", "validateUrl", "InetAddress"],
        "query": "allowlist whitelist isPrivateAddress validateUrl InetAddress SSRF"
    },
    # Missing Auth
    "862": {
        "code_patterns": ["@PreAuthorize", "@Secured", "@RolesAllowed", "hasRole", "isAuthenticated", "SecurityContext"],
        "query": "PreAuthorize Secured RolesAllowed hasRole isAuthenticated authorization"
    },
    # Cleartext Transmission
    "319": {
        "code_patterns": ["https", "TLS", "SSLContext", "HttpsURLConnection", "ssl", "HTTPS"],
        "query": "https TLS SSLContext HttpsURLConnection ssl secure transport"
    },
}

def _get_mitigation_query(cwe_id):
    """Get CWE-specific RAG query that searches for actual mitigation code patterns."""
    cwe_num = str(cwe_id).replace("CWE-", "").strip()
    if cwe_num in CWE_MITIGATION_PATTERNS:
        return CWE_MITIGATION_PATTERNS[cwe_num]["query"]
    # Fallback: generic security query
    return "validation sanitization security filter middleware check"


# -------------------------
# Segment 3: The Verifier Agent — Balanced RAG + LLM Verification
# -------------------------
def run_verifier_agent(parsed_alerts, vectordb, groq_key):
    """
    Phase 3: The Context Verifier.
    Uses the Vector DB to search for mitigating controls across the entire repo.
    Uses 8b model for higher rate limits (500k TPD vs 70b's 100k TPD).
    Compensates with a strict, detailed prompt to reduce false mitigations.
    """
    if not parsed_alerts or not vectordb:
        return "Verification skipped: No alerts or vector database available.", []

    # Use 8b-instant: 500k tokens/day limit vs 70b's 100k — handles large repos
    llm = ChatOpenAI(
        model="llama-3.1-8b-instant",
        api_key=groq_key,
        base_url="https://api.groq.com/openai/v1",
        temperature=0.0
    )

    verified_results = []
    metrics = []
    retriever = vectordb.as_retriever(search_kwargs={"k": 8})

    # RATE LIMITING — 1 finding at a time, 3s between calls (8b has generous limits)
    CHUNK_SIZE = 1
    SLEEP_TIME = 3

    for i in range(0, len(parsed_alerts), CHUNK_SIZE):
        chunk = parsed_alerts[i:i + CHUNK_SIZE]

        for alert in chunk:
            vuln_name = alert.get('vulnerability', 'vulnerability')
            file_name = alert.get('file', 'code')
            cwe = alert.get('cwe', '').strip('CWE-')
            owasp = alert.get('owasp_category', '')
            message = alert.get('message', '')
            vuln_short = vuln_name.split('.')[-1].lower()

            # CWE-SPECIFIC RAG: Search for actual mitigation code patterns
            mitigation_query = _get_mitigation_query(cwe)

            # Query 1: CWE-specific mitigation patterns
            search_query_1 = mitigation_query
            # Query 2: The vulnerable file itself + its imports
            search_query_2 = f"{file_name} import class extends implements"
            # Query 3: Security config/filters in the project
            search_query_3 = f"security filter config middleware interceptor"

            try:
                docs_1 = retriever.invoke(search_query_1)
                docs_2 = retriever.invoke(search_query_2)
                docs_3 = retriever.invoke(search_query_3)

                # Merge and deduplicate retrieved docs
                all_docs = docs_1 + docs_2 + docs_3
                seen_sources = set()
                unique_docs = []
                for d in all_docs:
                    src = d.metadata.get('source', '')
                    if src not in seen_sources:
                        seen_sources.add(src)
                        unique_docs.append(d)

                unique_docs = unique_docs[:12]

                if not unique_docs:
                    combined_context = "(No relevant context found in repository)"
                else:
                    context_texts = [f"File: {d.metadata.get('source', 'Unknown')}\n{d.page_content}" for d in unique_docs]
                    combined_context = "\n---\n".join(context_texts)
            except Exception as rag_err:
                combined_context = f"(RAG context unavailable: {str(rag_err)})"

            # Extract method name for Java files
            method_name = "N/A"
            full_path = alert.get('full_path', '')
            if full_path.endswith('.java'):
                method_name = extract_java_method_info(full_path, alert.get('line', 0))

            # STRICT PROMPT — prevents both false validations AND false mitigations
            system_prompt = f"""You are a security code reviewer. Determine whether a vulnerability flagged by a static analyzer is REAL (VALIDATED) or has been MITIGATED by existing code.

VULNERABILITY UNDER REVIEW:
- File: {file_name}
- Method: {method_name}
- Type: {vuln_short}
- CWE: CWE-{cwe}
- Scanner Message: {message}
- Flagged Code:
```
{alert.get('code_snippet', 'N/A')}
```

CODEBASE CONTEXT (retrieved from repository):
{combined_context}

STRICT RULES — You MUST follow these:
1. A mitigation MUST be a SPECIFIC function, class, or config that DIRECTLY prevents the CWE-{cwe} attack vector. Name it exactly.
2. The following are NOT mitigations — do NOT use them as evidence for MITIGATED:
   - String truncation or length limits (attackers can craft payloads within any length)
   - Test infrastructure (DomSanitizer, LoginGuard, mock objects in *.spec.* or *Test.* files)
   - "Might be defined elsewhere" or "possibly loaded securely" — if you cannot SEE the mitigation code, it does NOT exist
   - Being "part of a challenge" or "test scenario" — the code is still vulnerable
   - Unrelated security features (e.g., DomSanitizer does NOT mitigate hardcoded credentials)
   - localStorage or sessionStorage usage (these do NOT mitigate hardcoded secrets/tokens)
3. For hardcoded secrets/credentials (CWE-798, CWE-321): The secret MUST be loaded from environment variables, a vault, or external config. If the secret value is visible in the code, it is VALIDATED.
4. For SQL injection (CWE-89): Only parameterized queries/prepared statements count. String replacement/regex filtering is NOT sufficient.
5. For XSS (CWE-79): Only proper output encoding (escapeHtml, htmlEscape) or Content Security Policy counts.
6. If the mitigation is INCOMPLETE or BYPASSABLE, mark as VALIDATED with MEDIUM confidence.
7. When in doubt, mark as VALIDATED — it is safer to flag a potential issue than to miss a real one.

OUTPUT (use exactly this format):
### Verification: {vuln_short}
**File:** {file_name}
**Method:** {method_name}
**CWE:** CWE-{cwe}
**Status:** [VALIDATED or MITIGATED]
**Confidence:** [HIGH / MEDIUM / LOW]
**Evidence:** [Exact function/class that mitigates, or exact dangerous pattern that remains]
**Reasoning:** [2-3 sentences]
---
"""

            try:
                messages = [HumanMessage(content=system_prompt)]
                response = llm.invoke(messages)
                res_text = response.content
                verified_results.append(res_text)

                # Extract status — balanced fallback
                status_match = re.search(r'\*\*Status:\*\*\s*(VALIDATED|MITIGATED)', res_text)
                if status_match:
                    status = status_match.group(1)
                else:
                    v_count = res_text.upper().count("VALIDATED")
                    m_count = res_text.upper().count("MITIGATED")
                    if v_count > m_count:
                        status = "VALIDATED"
                    elif m_count > v_count:
                        status = "MITIGATED"
                    else:
                        status = "UNCERTAIN"

                # Extract confidence
                confidence_match = re.search(r'\*\*Confidence:\*\*\s*(HIGH|MEDIUM|LOW)', res_text)
                confidence = confidence_match.group(1) if confidence_match else "LOW"

                # Extract method name for tracking
                method_match = re.search(r'\*\*Method:\*\*\s*(\w+)', res_text)
                method_extracted = method_match.group(1) if method_match else method_name

                metrics.append({
                    "Vulnerability": vuln_name,
                    "File": file_name,
                    "OWASP Category": owasp,
                    "CWE_ID": f"CWE-{cwe}",
                    "Phase 1 Scanner": "Detected",
                    "Phase 3 Prediction": status,
                    "Confidence": confidence,
                    "Reasoning": res_text,
                    "Method": method_extracted
                })
            except Exception as e:
                verified_results.append(f"### Verification: {vuln_name}\n**Status:** ERROR\n**Reasoning:** API Rate Limit or Execution Error - {str(e)}\n---")
                metrics.append({
                    "Vulnerability": vuln_name,
                    "File": file_name,
                    "OWASP Category": owasp,
                    "CWE_ID": f"CWE-{cwe}",
                    "Phase 1 Scanner": "Detected",
                    "Phase 3 Prediction": "Error",
                    "Confidence": "N/A",
                    "Reasoning": str(e),
                    "Method": method_name
                })

        # Rate limiting between chunks
        if i + CHUNK_SIZE < len(parsed_alerts):
            try:
                time.sleep(SLEEP_TIME)
            except KeyboardInterrupt:
                break

    return "\n".join(verified_results), metrics
