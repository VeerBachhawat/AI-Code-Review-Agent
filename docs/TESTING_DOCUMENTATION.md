# SentinelAI — Testing & Quality Assurance Documentation

## 1. Test Environment

- **OS**: Windows 11 x64
- **Python Runtime**: Python 3.14 / Python 3.10 virtual environment (`.venv`)
- **Web Framework**: FastAPI 0.109+
- **LLM Service**: Ollama Qwen3:8b (`http://localhost:11434/v1/`)
- **Vector Database**: ChromaDB (`chromadb`)
- **Test Framework**: Python `unittest` standard library, FastAPI `TestClient` (HTTPX)

---

## 2. Test Methodology

SentinelAI utilizes an end-to-end testing strategy:
1. **Static Analyzer Tests**: Verifies AST parsing and regex rule accuracy.
2. **Orchestrator Pipeline Tests**: Verifies multi-agent execution, finding deduplication, and score calculation algorithms.
3. **LLM & Remediation Tests**: Verifies batch remediation format, zero-placeholder enforcement, and prompt safety.
4. **PR Summary Tests**: Verifies count fidelity between findings and qualitative PR summaries.
5. **RAG & Assistant Tests**: Verifies grounding, context hierarchy, and line-matching precision.
6. **Report Generation Tests**: Verifies PDF (ReportLab A4 single-page layout) and HTML structure.
7. **API Integration Tests**: Verifies HTTP status codes, payload structures, and file upload endpoints.

---

## 3. Python Test Samples

Sample tested in `tests/test_code_analysis.py` and `tests/test_security.py`:
```python
import os
import eval_module

def handle_user_login(user_input):
    DB_PASSWORD = "SuperSecretPassword123!"
    result = eval(user_input)
    return result
```

**Expected Detections**:
- Critical: `eval()` dynamic code evaluation (Line 5).
- High: Hardcoded credential `DB_PASSWORD` (Line 4).
- Low: Unused import `eval_module` (Line 2).

---

## 4. Java Test Samples

Sample tested in `tests/test_security.py`:
```java
import java.sql.*;

public class UserAuth {
    private String dbPass = "HardcodedJavaSecret123!";
    
    public ResultSet getUser(String username, Statement stmt) throws Exception {
        String query = "SELECT * FROM users WHERE username = '" + username + "'";
        return stmt.executeQuery(query);
    }
}
```

**Expected Detections**:
- Critical: SQL Injection via query concatenation (Line 7).
- High: Hardcoded credential `dbPass` (Line 4).

---

## 5. Test Suite Breakdown & Verification Results

| Test Module | Test Focus | Total Tests | Status |
|---|---|---|---|
| `test_api.py` | FastAPI Endpoints & Health Check | 10 | **PASS** |
| `test_code_analysis.py` | Python AST Metrics & Java Pattern Quality Rules | 5 | **PASS** |
| `test_security.py` | Python & Java Security Vulnerabilities | 6 | **PASS** |
| `test_orchestrator.py` | Multi-Agent Pipeline & Score Calculations | 4 | **PASS** |
| `test_remediation.py` | LLM Remediation & Deterministic Fallbacks | 3 | **PASS** |
| `test_pr_summary.py` | PR Summary Generation & Count Fidelity | 3 | **PASS** |
| `test_rag_assistant.py` | ChromaDB Retrieval & Assistant Knowledge | 4 | **PASS** |
| `test_reports.py` | Single-page PDF & Responsive HTML Generators | 4 | **PASS** |
| `test_prompt_quality.py` | Prompt Quality (Types A–I) & Context Priority | 10 | **PASS** |

**Total Test Suite Execution**: 49 tests executed — 100% Pass Rate.

---

## 6. Detailed Test Scenarios

### Syntax-Error Tests
- Tested in `test_api.py`: Submitting invalid syntax (`def broken_function(`) correctly triggers HTTP 422 Unprocessable Content with exact syntax error details.

### Code Quality Tests
- Verified AST cyclomatic complexity calculations, Halstead volume metrics, maintainability scores, and unused variable/import detection.

### Security Vulnerability Tests
- Verified AST node detection for `eval()`, hardcoded credentials, weak hashing (`md5`), command injection (`subprocess.Popen(shell=True)`), SQL injection, and XSS.

### Remediation & Zero-Placeholder Tests
- Verified that generated remediations contain exact variable names (`DB_PASSWORD = os.getenv('DB_PASSWORD')`) and zero generic comments (`# Example code`).

### PR Summary & Count Fidelity Tests
- Verified that PR summaries accurately report finding counts (e.g. 1 Critical, 1 High) and never output misleading critical warnings when Critical count is 0.

### RAG & Conversational Assistant Tests
- Verified that assistant responses prioritize user code as DATA and respond with explicit "finding not found on line X" when an invalid line is queried.

### Report Generation Tests
- Verified that ReportLab generates a valid PDF binary fitting strictly on a single A4 page and HTML generator compiles valid HTML structure.

### Fallback Tests
- Verified that when Ollama is offline or experiences a timeout, deterministic rule-based fallback engines seamlessly populate remediations and PR summaries.

---

## 7. Performance Observations

- **AST & Pattern Analysis**: Extremely fast ($\sim 0.01$ seconds per file).
- **Report Generation**: PDF generation takes $\sim 0.15$ seconds; HTML takes $\sim 0.02$ seconds.
- **LLM Batch Remediation (Ollama CPU)**: Takes $\sim 15 - 60$ seconds depending on system hardware load.
- **Conversational Assistant Chat (Ollama CPU)**: Takes $\sim 5 - 15$ seconds per turn.

---

## 8. Known Limitations

- **Java Static Analysis**: Java rule engine relies on regex pattern matching rather than AST compilation.
- **Local Inference Latency**: Ollama CPU inference speed is bound by local hardware capabilities.
