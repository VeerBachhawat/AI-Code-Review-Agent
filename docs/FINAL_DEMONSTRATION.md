# SentinelAI — Final Demonstration Package

This document contains three distinct, production-validated code samples demonstrating SentinelAI's capabilities across Code Quality, Security Vulnerabilities, and Java Enterprise analysis.

---

## Sample 1: Simple / Code Quality Analysis (Python)

### 1. Submitted Code
```python
import os
import sys
import unused_helper

def calculate_discount(price, customer_type):
    # Unused variable
    discount_rate = 0.05
    
    if customer_type == "VIP":
        final_price = price * 0.80
    elif customer_type == "REGULAR":
        final_price = price * 0.95
    else:
        final_price = price
        
    return final_price
```

### 2. Pipeline Execution Results
- **Auto-Detected Language**: `python`
- **Security Score**: `100.0 / 100`
- **Code Quality Score**: `82.0 / 100`

### 3. Detected Findings
- **Finding 1**: Unused import `sys` on line 2 (Severity: `Low`, Agent: `CodeAnalysisAgent`).
- **Finding 2**: Unused import `unused_helper` on line 3 (Severity: `Low`, Agent: `CodeAnalysisAgent`).
- **Finding 3**: Unused local variable `discount_rate` on line 7 (Severity: `Low`, Agent: `CodeAnalysisAgent`).

### 4. Automated Remediation
- **Problem**: Import `unused_helper` and variable `discount_rate` are defined but never referenced.
- **What to Change**: Remove unused imports on lines 2–3 and unused variable assignment on line 7.
- **Corrected Snippet**:
```python
import os

def calculate_discount(price, customer_type):
    if customer_type == "VIP":
        final_price = price * 0.80
    elif customer_type == "REGULAR":
        final_price = price * 0.95
    else:
        final_price = price
        
    return final_price
```

### 5. PR Summary
- **Overall Status**: `APPROVED`
- **Executive Summary**: "Code quality review passed with minor style observations. Zero security vulnerabilities detected."
- **Estimated Remediation Effort**: `< 5 minutes`

---

## Sample 2: Application Security Analysis (Python)

### 1. Submitted Code
```python
import os

def authenticate_and_execute(user_input):
    DB_PASSWORD = "SuperSecretAdminPassword123!"
    
    print("Authenticating user...")
    result = eval(user_input)
    return result
```

### 2. Pipeline Execution Results
- **Auto-Detected Language**: `python`
- **Security Score**: `60.0 / 100`
- **Code Quality Score**: `88.0 / 100`

### 3. Detected Security Vulnerabilities
- **Finding 1**: Use of `eval()` allows arbitrary dynamic code execution on line 7 (Severity: `Critical`, Agent: `SecurityAgent`).
- **Finding 2**: Hardcoded password string `DB_PASSWORD` on line 4 (Severity: `High`, Agent: `SecurityAgent`).

### 4. AI Remediation & Corrected Code
- **Problem**: `eval()` on line 7 allows attackers to execute arbitrary system code with application privileges.
- **What to Change**: Replace `eval(user_input)` with `ast.literal_eval(user_input)` and replace hardcoded string on line 4 with `os.getenv("DB_PASSWORD")`.
- **Complete Corrected Code**:
```python
import os
import ast

def authenticate_and_execute(user_input):
    DB_PASSWORD = os.getenv("DB_PASSWORD")
    
    print("Authenticating user...")
    result = ast.literal_eval(user_input)
    return result
```

### 5. RAG Explanation & AI Assistant Conversation
- **Developer Prompt**: *"Why is eval dangerous and what does OWASP recommend?"*
- **SentinelAI RAG Answer**: *"The `eval()` function evaluates arbitrary string expressions as Python code. If user input reaches `eval()`, an attacker can inject malicious code (CWE-95). OWASP A03:2021 (Injection) recommends avoiding dynamic evaluation functions entirely and using strict schema validation or `ast.literal_eval()` for safe string literal evaluation."*

### 6. PDF Executive Report
- Generated Single-Page A4 PDF (`report_sample2.pdf`) containing Security Score Gauge (`60/100`), Critical Finding Summary, and Remediation Roadmap.

---

## Sample 3: Enterprise Java Analysis

### 1. Submitted Code
```java
import java.sql.*;
import java.util.*;

public class UserDAO {
    private String dbPassword = "HardcodedJavaPassword123!";

    public ResultSet findUser(String username, Statement stmt) throws Exception {
        String sql = "SELECT * FROM users WHERE username = '" + username + "'";
        return stmt.executeQuery(sql);
    }
}
```

### 2. Pipeline Execution Results
- **Auto-Detected Language**: `java`
- **Security Score**: `60.0 / 100`
- **Code Quality Score**: `85.0 / 100`

### 3. Detected Java Vulnerabilities
- **Finding 1**: SQL Injection vulnerability via string concatenation on line 8 (Severity: `Critical`, Agent: `SecurityAgent`).
- **Finding 2**: Hardcoded credential `dbPassword` on line 5 (Severity: `High`, Agent: `SecurityAgent`).

### 4. Automated Remediation & Corrected Code
- **Problem**: Unsanitized string concatenation in SQL queries allows SQL injection attacks.
- **What to Change**: Replace `Statement.executeQuery` with a `PreparedStatement` using parameterized placeholder queries (`?`).
- **Corrected Snippet**:
```java
import java.sql.*;

public class UserDAO {
    private String dbPassword = System.getenv("DB_PASSWORD");

    public ResultSet findUser(String username, Connection conn) throws Exception {
        String sql = "SELECT * FROM users WHERE username = ?";
        PreparedStatement stmt = conn.prepareStatement(sql);
        stmt.setString(1, username);
        return stmt.executeQuery();
    }
}
```

### 5. Exported Reports
- **HTML Report**: Responsive web report with interactive severity charts.
- **PDF Report**: Executive single-page A4 summary.
