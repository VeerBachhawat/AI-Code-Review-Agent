from fastapi import FastAPI
from pydantic import BaseModel
from fastapi import UploadFile, File
from agents.orchestrator import Orchestrator

import ast

app = FastAPI(
    title="AI Code Review Agent",
    version="1.0"
)
orchestrator = Orchestrator()

class CodeInput(BaseModel):
    language: str
    code: str

@app.get("/")
def home():
    return {"message": "AI Code Review Agent Backend is Running!"}


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
        "message": "Language accepted (validation coming soon)."
    }
@app.post("/upload-file")
async def upload_file(file: UploadFile = File(...)):

    content = await file.read()
    code = content.decode("utf-8")

    filename = file.filename

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
                "error": str(e)
            }

    elif filename.endswith(".java"):

        import javalang

        try:

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
                "error": str(e)
            }

    else:

        return {
            "status": "Unsupported File Type"
        }
@app.post("/review-code")
def review_code(data: CodeInput):

    if data.language.lower() != "python":
        return {
            "status": "error",
            "message": "Currently only Python AI review is supported."
        }

    result = orchestrator.review(data.code)

    return {
        "status": "success",
        "language": data.language,
        "review": result
    }