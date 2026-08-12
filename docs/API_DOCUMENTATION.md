# SentinelAI — API Documentation

Base URL: `http://localhost:8001`

---

## Endpoint Summary

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/submit-code` | Validates syntax and detects language for submitted code snippet. |
| `POST` | `/upload-file` | Accepts file uploads (`.py` or `.java`) and validates contents. |
| `POST` | `/review-code` | Executes complete multi-agent review pipeline. |
| `POST` | `/chat` | Interacts with Conversational AI Assistant using hybrid RAG. |
| `POST` | `/explain-finding` | Explains a specific finding line with grounded context. |
| `POST` | `/ask-remediation` | Requests specific remediation instructions for a finding. |
| `GET`  | `/download-report/{report_id}.pdf` | Downloads single-page executive A4 PDF code review report. |
| `GET`  | `/download-report/{report_id}.html` | Downloads responsive HTML code review report. |
| `GET`  | `/health` | Returns system health status and Ollama availability. |
| `GET`  | `/history` | Returns list of stored review sessions. |

---

## 1. POST /submit-code

**Purpose**: Accepts raw code text, validates syntax, auto-detects programming language (`python` or `java`), and returns code statistics.

### Request Body (`application/json`)
```json
{
  "code": "import os\nDB_PASSWORD = 'Secret123!'\nresult = eval(user_input)",
  "language": "python"
}
```

### Success Response (`200 OK`)
```json
{
  "valid": true,
  "language": "python",
  "line_count": 3,
  "character_count": 68,
  "message": "Code is valid python code."
}
```

### Error Response (`422 Unprocessable Content`)
```json
{
  "detail": "Syntax error in python code on line 2: unexpected EOF while parsing"
}
```

---

## 2. POST /upload-file

**Purpose**: Handles file upload for Python (`.py`) or Java (`.java`) source files.

### Request Format (`multipart/form-data`)
- `file`: Source file upload (`.py` or `.java`).

### Success Response (`200 OK`)
```json
{
  "filename": "vulnerable_app.py",
  "language": "python",
  "code": "import os\nDB_PASSWORD = 'Secret123!'\nresult = eval(user_input)",
  "line_count": 3,
  "character_count": 68,
  "valid": true
}
```

### Error Response (`400 Bad Request`)
```json
{
  "detail": "Unsupported file format. Please upload .py or .java files."
}
```

---

## 3. POST /review-code

**Purpose**: Runs the full SentinelAI review pipeline, executing static AST analysis, security scanning, scoring, LLM remediation generation, PR summary generation, and report compilation.

### Request Body (`application/json`)
```json
{
  "code": "import os\nDB_PASSWORD = 'SuperSecretPassword123!'\nresult = eval(user_input)",
  "language": "python"
}
```

### Success Response (`200 OK`)
```json
{
  "id": "review_20260812_153022",
  "timestamp": "2026-08-12T15:30:22Z",
  "language": "python",
  "security_score": 60.0,
  "code_quality_score": 85.0,
  "total_findings": 2,
  "severity_counts": {
    "Critical": 1,
    "High": 1,
    "Medium": 0,
    "Low": 0
  },
  "findings": [
    {
      "id": 1,
      "line": 3,
      "issue": "Use of eval() function allows arbitrary code execution",
      "severity": "Critical",
      "agent": "SecurityAgent",
      "explanation": "Evaluating untrusted string input can lead to Remote Code Execution.",
      "offending_code_snippet": "result = eval(user_input)"
    },
    {
      "id": 2,
      "line": 2,
      "issue": "Hardcoded credential DB_PASSWORD detected",
      "severity": "High",
      "agent": "SecurityAgent",
      "explanation": "Hardcoded passwords in source code expose secrets to repository access.",
      "offending_code_snippet": "DB_PASSWORD = 'SuperSecretPassword123!'"
    }
  ],
  "remediations": [
    {
      "id": 1,
      "problem": "The eval() function executes arbitrary code from user input.",
      "why_it_matters": "Allows attackers to execute malicious code with application privileges.",
      "what_to_change": "Replace eval() with ast.literal_eval() or safe parsing.",
      "improved_code": "result = ast.literal_eval(user_input)",
      "best_practice": "Never pass unvalidated user input to eval().",
      "references": ["OWASP A03:2021 - Injection", "CWE-95"]
    }
  ],
  "pr_summary": {
    "overall_status": "NEEDS_WORK",
    "executive_summary": "The PR contains 1 Critical security vulnerability and 1 High severity issue.",
    "top_risks": [
      "Critical vulnerability: eval() execution on line 3"
    ],
    "code_quality_summary": "Code structure is concise but contains security risks.",
    "security_summary": "Security score is 60.0/100 due to eval usage and hardcoded password.",
    "positive_observations": ["Code is concise."],
    "recommended_next_steps": ["Replace eval with ast.literal_eval.", "Use os.getenv for DB_PASSWORD."],
    "estimated_remediation_effort": "15-30 minutes",
    "developer_comment": "Please address the Critical eval vulnerability before merging."
  },
  "report_ids": {
    "pdf": "report_20260812_153022",
    "html": "report_20260812_153022"
  }
}
```

---

## 4. POST /chat

**Purpose**: Interactive conversational AI assistant endpoint using hybrid RAG context hierarchy.

### Request Body (`application/json`)
```json
{
  "question": "How do I fix the eval issue on line 3?",
  "optional_code": "import os\nresult = eval(user_input)",
  "optional_findings": [
    {
      "id": 1,
      "line": 3,
      "issue": "Use of eval() function allows arbitrary code execution",
      "severity": "Critical"
    }
  ],
  "remediations": [],
  "history": []
}
```

### Success Response (`200 OK`)
```json
{
  "answer": "To fix the `eval()` issue on line 3, replace `eval(user_input)` with `ast.literal_eval(user_input)` or parse the input strictly. Using `ast.literal_eval` safely evaluates literal structures without executing arbitrary code.",
  "sources": [
    "OWASP Top 10 - Injection (A03:2021)",
    "Python AST Documentation"
  ],
  "model_used": "qwen3:8b",
  "provider": "Ollama"
}
```

---

## 5. POST /explain-finding

**Purpose**: Generates a detailed explanation for a specific finding.

### Request Body (`application/json`)
```json
{
  "finding_id": 1,
  "line_number": 3,
  "issue": "Use of eval() function allows arbitrary code execution",
  "code_snippet": "result = eval(user_input)"
}
```

### Success Response (`200 OK`)
```json
{
  "explanation": "Line 3 calls `eval(user_input)`. In Python, `eval()` executes arbitrary string input as Python code. If `user_input` comes from an untrusted source, an attacker can pass system commands such as `__import__('os').system('rm -rf /')`, leading to complete server compromise.",
  "severity": "Critical",
  "cwe_id": "CWE-95"
}
```

---

## 6. POST /ask-remediation

**Purpose**: Generates targeted remediation advice for a specific finding.

### Request Body (`application/json`)
```json
{
  "finding_id": 1,
  "issue": "Hardcoded credential DB_PASSWORD detected",
  "code_snippet": "DB_PASSWORD = 'SuperSecretPassword123!'"
}
```

### Success Response (`200 OK`)
```json
{
  "remediation": {
    "problem": "Password assignment on line 2 uses hardcoded string 'SuperSecretPassword123!'.",
    "why_it_matters": "Hardcoded credentials in source code can be exposed in version control repositories.",
    "what_to_change": "Replace hardcoded string with environment variable lookup using os.getenv().",
    "improved_code": "DB_PASSWORD = os.getenv('DB_PASSWORD')",
    "best_practice": "Store secrets in environment variables or key vaults.",
    "references": ["OWASP A07:2021", "CWE-798"]
  }
}
```

---

## 7. GET /download-report/{report_id}.pdf

**Purpose**: Serves the single-page executive A4 PDF code review report.

- **URL Parameter**: `report_id` (string, e.g. `report_20260812_153022`)
- **Response**: Binary PDF file (`application/pdf`) with `Content-Disposition: attachment; filename="SentinelAI_Report_{report_id}.pdf"`.

---

## 8. GET /download-report/{report_id}.html

**Purpose**: Serves the responsive HTML code review report.

- **URL Parameter**: `report_id` (string, e.g. `report_20260812_153022`)
- **Response**: HTML file (`text/html`).

---

## 9. GET /health

**Purpose**: Health check endpoint returning backend status and Ollama model connectivity.

### Success Response (`200 OK`)
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "ollama": {
    "status": "connected",
    "provider": "ollama",
    "model": "qwen3:8b",
    "model_available": true
  }
}
```

---

## 10. GET /history

**Purpose**: Returns past review session logs.

### Success Response (`200 OK`)
```json
{
  "total_reviews": 1,
  "reviews": [
    {
      "id": "review_20260812_153022",
      "timestamp": "2026-08-12T15:30:22Z",
      "language": "python",
      "security_score": 60.0,
      "code_quality_score": 85.0,
      "total_findings": 2
    }
  ]
}
```
