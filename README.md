# AI Code Review & Security Analysis Agent

This project is a part of my internship and focuses on making code reviews easier, faster, and more secure.

Instead of manually checking source code for coding mistakes and security issues, this system automatically analyzes the code and generates a review report. It uses multiple agents to perform different types of analysis and combines their results into a single response.

Currently, the project supports Python code analysis and includes a Retrieval-Augmented Generation (RAG) knowledge base that will be used for AI-powered explanations in future milestones.

---

## Project Objective

The goal of this project is to build an intelligent code review system that can:

- Detect common coding mistakes
- Identify security vulnerabilities
- Provide a structured review report
- Reduce the time required for manual code reviews
- Build a foundation for AI-assisted code review

---

## Features

### Code Analysis

The Code Analysis Agent checks the quality of Python code by identifying:

- Poor variable names
- Functions with too many parameters
- Large classes
- Basic code quality issues

### Security Analysis

The Security Agent scans the code for common security problems such as:

- Use of `eval()`
- Use of `exec()`
- Hardcoded passwords
- Hardcoded API keys
- `subprocess(shell=True)`

### Multi-Agent Architecture

Instead of using one large module, the project follows a multi-agent approach.

- One agent performs code quality analysis.
- Another agent performs security analysis.
- The Orchestrator combines the results and returns a single review report.

### RAG Knowledge Base

A knowledge base has been created using secure coding guidelines and best practice documents.

The documents are:

- Split into smaller chunks
- Converted into embeddings
- Stored inside ChromaDB

This knowledge base will be used in future milestones to provide AI-generated explanations and secure coding recommendations.

---

## Tech Stack

**Backend**

- Python
- FastAPI

**Code Analysis**

- Python AST

**RAG**

- LangChain
- ChromaDB
- Sentence Transformers

**Concurrency**

- ThreadPoolExecutor

**Version Control**

- Git & GitHub

---

## Project Structure

```text
AI-Code-Review-Agent
│
├── backend
│   ├── agents
│   │   ├── code_analysis_agent.py
│   │   ├── security_agent.py
│   │   └── orchestrator.py
│   │
│   ├── documents
│   ├── rag
│   ├── vector_db
│   └── main.py
│
├── test_files
├── requirements.txt
└── README.md
```

---

## Installation

Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/AI-Code-Review-Agent.git
```

Move into the project folder

```bash
cd AI-Code-Review-Agent
```

Create a virtual environment

```bash
python -m venv .venv
```

Activate it

**Windows**

```bash
.venv\Scripts\activate
```

Install the required packages

```bash
pip install -r requirements.txt
```

---

## Running the Project

Go to the backend folder

```bash
cd backend
```

Start the FastAPI server

```bash
python -m uvicorn main:app --reload
```

Open your browser and visit

```
http://127.0.0.1:8000/docs
```

Swagger UI will open, where you can test all the available APIs.

---

## Creating the Knowledge Base

Move to the RAG folder

```bash
cd backend/rag
```

Run

```bash
python ingest.py
```

This will read all secure coding documents, create embeddings, and store them in the vector database.

---

## Querying the Knowledge Base

```bash
python query.py
```

You can then ask questions like:

```
What is SQL Injection?
```

---

## Available APIs

| Method | Endpoint | Description |
|---------|----------|-------------|
| GET | `/` | Check whether the server is running |
| POST | `/submit-code` | Submit source code |
| POST | `/upload-file` | Upload Python or Java files |
| POST | `/review-code` | Perform complete code review |

---

## Example Request

```json
{
    "language": "python",
    "code": "password='admin123'\na=10\nb=20\neval('2+2')"
}
```

---

## Example Response

```json
{
    "status": "success",
    "review": {
        "summary": {
            "total_findings": 4,
            "critical": 1,
            "high": 1,
            "medium": 0,
            "low": 2
        }
    }
}
```

---

## Future Improvements

Some features planned for the next milestones are:

- AI-generated explanations using LLMs
- Secure code fix suggestions
- Complete GitHub repository scanning
- Multi-language support
- PDF report generation
- Better code quality metrics

---

## Author

**Veer Jain**

Internship Project

AI Code Review & Security Analysis Agent

---

## Note

This project is being developed as part of my internship to explore AI-assisted code review using a modular multi-agent architecture and Retrieval-Augmented Generation (RAG).