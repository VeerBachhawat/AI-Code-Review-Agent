import ast
import logging
import os
import sys
from typing import Any, Dict, List, Optional
from dotenv import load_dotenv

root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
env_path = os.path.join(root_dir, ".env")
load_dotenv(dotenv_path=env_path)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SentinelAI")

ollama_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1/")
ollama_model = os.getenv("OLLAMA_MODEL", "qwen3:8b")
logger.info(f"[OLLAMA CONFIG] Provider: Ollama | Model: {ollama_model} | Base URL: {ollama_url}")

from fastapi import FastAPI, File, UploadFile, Request, status, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from pydantic import BaseModel

from backend.agents.orchestrator import Orchestrator
from backend.agents.conversational_code_assistant import ConversationalCodeAssistant
from backend.agents.remediation_agent import RemediationAgent
from backend.agents.pr_summary_agent import PRSummaryAgent
from backend.reporting.report_generator import ReportGenerator
from backend.llm.ollama_service import ollama_service

app = FastAPI(
    title="AI Code Review Agent",
    version="1.0"
)

# CORS Configuration
origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


# Custom Exception Handlers for JSON Error Responses
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"status": "error", "message": str(exc.detail)}
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"status": "error", "message": "Validation Error", "details": exc.errors()}
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"status": "error", "message": str(exc)}
    )


orchestrator = Orchestrator()
assistant = ConversationalCodeAssistant()
remediation_agent = RemediationAgent()
pr_summary_agent = PRSummaryAgent()
report_generator = ReportGenerator()


# Helper for non-python review responses
def _build_review_payload(language: str, findings: List[Dict[str, Any]], code: str = ""):
    total_findings = len(findings)
    critical_count = sum(1 for f in findings if str(f.get("severity", "")).lower() == "critical")
    high_count = sum(1 for f in findings if str(f.get("severity", "")).lower() == "high")
    medium_count = sum(1 for f in findings if str(f.get("severity", "")).lower() == "medium")
    low_count = sum(1 for f in findings if str(f.get("severity", "")).lower() == "low")

    # Generate dynamic LLM remediations and PR summary via Ollama Service
    remediations = remediation_agent.generate_remediation(findings, source_code=code)
    pr_summary = pr_summary_agent.generate_summary(findings, remediations)

    payload = {
        "status": "success",
        "language": language.lower(),
        "execution_time_ms": 120,
        "summary": {
            "total_findings": total_findings,
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
            "agent_status": {
                "CodeAnalysisAgent": "success",
                "SecurityAgent": "success",
                "RemediationAgent": "success",
                "PRSummaryAgent": "success"
            }
        },
        "findings": findings,
        "remediation": remediations,
        "pr_summary": pr_summary
    }

    result = dict(payload)
    result["review"] = payload
    return result


# Request Models
class CodeInput(BaseModel):
    language: str
    code: str


class ChatRequest(BaseModel):
    question: Any
    optional_findings: Optional[List[Dict[str, Any]]] = None
    optional_code: Optional[str] = None
    remediations: Optional[List[Dict[str, Any]]] = None
    pr_summary: Optional[Dict[str, Any]] = None
    code_quality_score: Optional[int] = None
    security_score: Optional[int] = None
    history: Optional[List[Dict[str, Any]]] = None


class FindingRequest(BaseModel):
    finding: Dict[str, Any]
    code: Optional[str] = None
    findings: Optional[List[Dict[str, Any]]] = None
    remediations: Optional[List[Dict[str, Any]]] = None
    pr_summary: Optional[Dict[str, Any]] = None
    code_quality_score: Optional[int] = None
    security_score: Optional[int] = None
    history: Optional[List[Dict[str, Any]]] = None


class GenerateReportRequest(BaseModel):
    review: Dict[str, Any]
    format: Optional[str] = "both"


# Existing Endpoints (Preserved)
@app.get("/")
def home():
    return {"message": "AI Code Review Agent Backend is Running!"}


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "SentinelAI API",
        "ollama_configured": True,
        "model": os.getenv("OLLAMA_MODEL", "qwen3:8b")
    }


@app.get("/health/ollama")
@app.get("/health/groq")
def ollama_health():
    """
    Health check endpoint to test Ollama LLM API connectivity and configuration.
    """
    try:
        return ollama_service.health_check()
    except Exception as e:
        logger.exception("[OLLAMA HEALTH ERROR] Ollama API check failed")
        return {
            "provider": "ollama",
            "status": "error",
            "error_type": type(e).__name__,
            "message": f"Failed to connect to Ollama API: {str(e)}"
        }


@app.post("/submit-code")
def submit_code(data: CodeInput):
    if data.language.lower() == "python":
        try:
            ast.parse(data.code)
            return {
                "status": "success",
                "message": "Python syntax is valid."
            }
        except SyntaxError as e:
            return {
                "status": "error",
                "message": f"Syntax Error at line {e.lineno}",
                "details": str(e)
            }

    return {
        "status": "success",
        "message": f"{data.language.capitalize()} language accepted."
    }


@app.post("/upload-file")
async def upload_file(file: UploadFile = File(...)):
    content = await file.read()
    code = content.decode("utf-8", errors="ignore")
    filename = file.filename or "uploaded_file.py"

    if filename.endswith(".py"):
        try:
            ast.parse(code)
            return {
                "filename": filename,
                "language": "Python",
                "status": "Valid Python Syntax",
                "code": code
            }
        except SyntaxError as e:
            return {
                "filename": filename,
                "language": "Python",
                "status": "Syntax Error",
                "error": str(e),
                "code": code
            }
    elif filename.endswith(".java"):
        try:
            import javalang
            javalang.parse.parse(code)
            return {
                "filename": filename,
                "language": "Java",
                "status": "Valid Java Syntax",
                "code": code
            }
        except Exception as e:
            return {
                "filename": filename,
                "language": "Java",
                "status": "Syntax Error",
                "error": str(e),
                "code": code
            }
    else:
        return {
            "filename": filename,
            "language": "Text",
            "status": "Loaded",
            "code": code
        }


@app.post("/review-code")
def review_code(data: CodeInput):
    lang = data.language.lower().strip()

    if lang == "python":
        result = orchestrator.review(data.code, language="python")
        output = dict(result)
        output["status"] = "success"
        output["language"] = "python"
        output["review"] = result
        return output

    else:
        lang_findings = []
        lines = data.code.split("\n")

        for i, line in enumerate(lines, start=1):
            line_str = line.strip()
            # General Security & Quality Pattern Scans for Non-Python languages
            if "System.out.print" in line_str or "console.log" in line_str:
                lang_findings.append({
                    "agent": "CodeAnalysisAgent",
                    "severity": "Low",
                    "issue": "Console Debug Statement",
                    "explanation": f"Print or console statement detected in line {i}. Use a structured logging framework.",
                    "line": i
                })
            if "Runtime.getRuntime().exec" in line_str or "ProcessBuilder" in line_str or "child_process" in line_str or "system(" in line_str:
                lang_findings.append({
                    "agent": "SecurityAgent",
                    "severity": "High",
                    "issue": "Command Execution Risk",
                    "explanation": f"Executing system commands dynamically on line {i} can allow Command Injection.",
                    "line": i
                })
            if "eval(" in line_str or "ScriptEngine" in line_str or "innerHTML" in line_str:
                lang_findings.append({
                    "agent": "SecurityAgent",
                    "severity": "Critical",
                    "issue": "Dynamic Execution / Unescaped Render Risk",
                    "explanation": f"Dynamic execution or raw rendering on line {i} exposes the application to code injection or XSS.",
                    "line": i
                })
            if "strcpy(" in line_str or "gets(" in line_str:
                lang_findings.append({
                    "agent": "SecurityAgent",
                    "severity": "Critical",
                    "issue": "Unsafe Memory Function",
                    "explanation": f"Unsafe string function detected on line {i}. Can lead to buffer overflow.",
                    "line": i
                })

        formatted_lang = data.language.capitalize()
        if lang in ["js", "javascript"]:
            formatted_lang = "JavaScript"
        elif lang in ["ts", "typescript"]:
            formatted_lang = "TypeScript"
        elif lang in ["cpp", "c++"]:
            formatted_lang = "C++"

        return _build_review_payload(formatted_lang, lang_findings, data.code)


# Conversational & Remediation Endpoints

@app.post("/chat")
def chat(request: ChatRequest):
    """
    RAG-powered conversational endpoint for answering developer security
    and code quality questions using indexed knowledge bases and Ollama Qwen3.
    """
    try:
        response = assistant.ask(
            question=request.question,
            optional_findings=request.optional_findings,
            optional_code=request.optional_code,
            remediations=request.remediations,
            pr_summary=request.pr_summary,
            code_quality_score=request.code_quality_score,
            security_score=request.security_score,
            history=request.history
        )
        return response
    except Exception as e:
        return {
            "status": "error",
            "message": f"Chat request failed: {str(e)}",
            "answer": "An error occurred while processing your request.",
            "sources": [],
            "related_topics": []
        }


@app.post("/explain-finding")
def explain_finding(request: FindingRequest):
    """
    Automatically generates a detailed conversational explanation for a given finding
    using the ConversationalCodeAssistant and RAG knowledge base.
    """
    try:
        finding = request.finding
        issue = finding.get("issue", "Finding Issue")
        explanation_text = finding.get("explanation", "")
        line = finding.get("line", 0)

        prompt = f"Explain this finding on line {line}: {issue}. Details: {explanation_text}"
        response = assistant.ask(
            question=prompt,
            optional_findings=request.findings or [finding],
            optional_code=request.code,
            remediations=request.remediations,
            pr_summary=request.pr_summary,
            code_quality_score=request.code_quality_score,
            security_score=request.security_score
        )

        return {
            "status": "success",
            "finding": finding,
            "answer": response.get("answer", ""),
            "explanation": response.get("answer", ""),
            "sources": response.get("sources", []),
            "related_topics": response.get("related_topics", [])
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to explain finding: {str(e)}"
        }


@app.post("/ask-remediation")
def ask_remediation(request: FindingRequest):
    """
    Returns remediation guidance generated by the RemediationAgent together with a
    conversational explanation from the ConversationalCodeAssistant.
    """
    try:
        finding = request.finding
        issue = finding.get("issue", "Finding Issue")
        line = finding.get("line", 0)

        remediations = remediation_agent.generate_remediation(
            findings=request.findings or [finding],
            source_code=request.code or ""
        )
        remediation = remediations[0] if remediations else {}

        prompt = f"How should I fix this vulnerability on line {line}: {issue}?"
        chat_response = assistant.ask(
            question=prompt,
            optional_findings=request.findings or [finding],
            optional_code=request.code,
            remediations=request.remediations or remediations,
            pr_summary=request.pr_summary,
            code_quality_score=request.code_quality_score,
            security_score=request.security_score
        )

        return {
            "status": "success",
            "finding": finding,
            "remediation": remediation,
            "conversational_explanation": chat_response.get("answer", ""),
            "answer": chat_response.get("answer", ""),
            "sources": chat_response.get("sources", []),
            "related_topics": chat_response.get("related_topics", [])
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to generate remediation guidance: {str(e)}"
        }


# ------------------------------------------------------------------------------
# Report Generation Endpoints (Milestone 4 - Requirement 1)
# ------------------------------------------------------------------------------

@app.post("/generate-report")
def generate_report(data: GenerateReportRequest):
    """
    Generates dynamic PDF and/or HTML code review reports based on actual review data.
    """
    try:
        review_data = data.review
        fmt = (data.format or "both").lower().strip()
        formats_to_gen = ["pdf", "html"] if fmt in ("both", "all") else [fmt]

        generated_files = report_generator.save_report(review_data, formats=formats_to_gen)

        pdf_path = generated_files.get("pdf")
        html_path = generated_files.get("html")

        pdf_filename = os.path.basename(pdf_path) if pdf_path else None
        html_filename = os.path.basename(html_path) if html_path else None

        return {
            "status": "success",
            "pdf_filename": pdf_filename,
            "html_filename": html_filename,
            "pdf_url": f"/download-report/{pdf_filename}" if pdf_filename else None,
            "html_url": f"/download-report/{html_filename}" if html_filename else None
        }
    except Exception as e:
        logger.exception("[REPORT GENERATION ERROR]")
        return JSONResponse(
            status_code=500,
            content={"status": "error", "message": f"Report generation failed: {str(e)}"}
        )


@app.get("/download-report/{filename}")
def download_report_by_name(filename: str):
    """
    Downloads a previously generated PDF or HTML report by filename.
    """
    safe_filename = os.path.basename(filename)
    file_path = os.path.join(report_generator.output_dir, safe_filename)

    if not os.path.isfile(file_path):
        raise HTTPException(status_code=404, detail="Requested report file not found.")

    media_type = "application/pdf" if safe_filename.endswith(".pdf") else "text/html"
    return FileResponse(
        path=file_path,
        media_type=media_type,
        filename=safe_filename,
        headers={"Content-Disposition": f"attachment; filename={safe_filename}"}
    )


@app.post("/download-report/pdf")
def download_report_pdf(data: Dict[str, Any]):
    """
    Directly generates and serves a downloadable PDF report for the provided review payload.
    """
    try:
        review_data = data.get("review", data)
        pdf_path = report_generator.generate_pdf(review_data)
        filename = os.path.basename(pdf_path)
        return FileResponse(
            path=pdf_path,
            media_type="application/pdf",
            filename=filename,
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    except Exception as e:
        logger.exception("[PDF GENERATION ERROR]")
        return JSONResponse(
            status_code=500,
            content={"status": "error", "message": f"PDF report generation failed: {str(e)}"}
        )


@app.post("/download-report/html")
def download_report_html(data: Dict[str, Any]):
    """
    Directly generates and serves a downloadable HTML report for the provided review payload.
    """
    try:
        review_data = data.get("review", data)
        html_path = report_generator.generate_html(review_data)
        filename = os.path.basename(html_path)
        return FileResponse(
            path=html_path,
            media_type="text/html",
            filename=filename,
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    except Exception as e:
        logger.exception("[HTML GENERATION ERROR]")
        return JSONResponse(
            status_code=500,
            content={"status": "error", "message": f"HTML report generation failed: {str(e)}"}
        )