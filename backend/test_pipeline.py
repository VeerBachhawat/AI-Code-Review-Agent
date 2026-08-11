import requests
import json

print("==================================================")
print("TEST 1: GET /health")
h_res = requests.get('http://127.0.0.1:8000/health')
print("  Status:", h_res.status_code)
print("  Body:  ", h_res.json())

print("==================================================")
print("TEST 2: GET /health/groq")
g_res = requests.get('http://127.0.0.1:8000/health/groq')
print("  Status:", g_res.status_code)
print("  Body:  ", g_res.json())

print("==================================================")
print("TEST 3: POST /review-code (PYTHON)")
sample_python = """password = "admin123"
user_input = input("Expression: ")
result = eval(user_input)
print(result)"""

r_res = requests.post('http://127.0.0.1:8000/review-code', json={'language': 'python', 'code': sample_python})
print("  Status:", r_res.status_code)
review = r_res.json().get('review', {})
print("  Total Findings:", len(review.get('findings', [])))
print("  PR Summary Status:", review.get('pr_summary', {}).get('overall_status'))

print("==================================================")
print("TEST 4: POST /review-code (JAVASCRIPT)")
sample_js = """import React from "react";
import ReactDOM from "react-dom/client";
import "./index.css";
import App from "./App";

const root = ReactDOM.createRoot(document.getElementById("root"));

root.render(
    <React.StrictMode>
        <App />
    </React.StrictMode>
);"""

js_res = requests.post('http://127.0.0.1:8000/review-code', json={'language': 'javascript', 'code': sample_js})
print("  Status:", js_res.status_code)
js_review = js_res.json().get('review', {})
print("  Language:", js_res.json().get('language'))
print("  Total Findings:", len(js_review.get('findings', [])))
print("  PR Summary Status:", js_review.get('pr_summary', {}).get('overall_status'))

print("==================================================")
print("TEST 5: POST /chat (Question 1)")
c1 = requests.post('http://127.0.0.1:8000/chat', json={'question': 'Explain SQL Injection.'})
print("  Status:", c1.status_code)
print("  Snippet:", c1.json().get('answer', '')[:150].replace('\n', ' '))

print("==================================================")
print("TEST 6: POST /chat (Question 2)")
c2 = requests.post('http://127.0.0.1:8000/chat', json={'question': 'Explain Cyclomatic Complexity.'})
print("  Status:", c2.status_code)
print("  Snippet:", c2.json().get('answer', '')[:150].replace('\n', ' '))

print("==================================================")
print("TEST 7: POST /chat (Question 3)")
c3 = requests.post('http://127.0.0.1:8000/chat', json={'question': 'Why is eval() dangerous?'})
print("  Status:", c3.status_code)
print("  Snippet:", c3.json().get('answer', '')[:150].replace('\n', ' '))

print("==================================================")
print("ALL TESTS COMPLETE!")
