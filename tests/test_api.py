import os
import time
import unittest
from fastapi.testclient import TestClient
from backend.main import app

SAMPLES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "samples"))


class TestAPIEndpoints(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)

    def test_home_and_health(self):
        r1 = self.client.get("/")
        self.assertEqual(r1.status_code, 200)
        self.assertIn("message", r1.json())

        r2 = self.client.get("/health")
        self.assertEqual(r2.status_code, 200)
        self.assertEqual(r2.json().get("status"), "healthy")

    def test_submit_code_python_valid(self):
        path = os.path.join(SAMPLES_DIR, "python", "clean_python.py")
        with open(path, "r", encoding="utf-8") as f:
            code = f.read()

        t0 = time.perf_counter()
        r = self.client.post("/submit-code", json={"language": "python", "code": code})
        elapsed = (time.perf_counter() - t0) * 1000

        self.assertEqual(r.status_code, 200)
        res = r.json()
        self.assertEqual(res.get("status"), "success")
        print(f"\n[PERF] /submit-code (Python valid): {elapsed:.2f} ms")

    def test_submit_code_python_invalid(self):
        path = os.path.join(SAMPLES_DIR, "python", "invalid_python.py")
        with open(path, "r", encoding="utf-8") as f:
            code = f.read()

        r = self.client.post("/submit-code", json={"language": "python", "code": code})
        self.assertEqual(r.status_code, 200)
        res = r.json()
        self.assertEqual(res.get("status"), "error")
        self.assertIn("Syntax Error", res.get("message", ""))

    def test_submit_code_java_valid(self):
        path = os.path.join(SAMPLES_DIR, "java", "clean_java.java")
        with open(path, "r", encoding="utf-8") as f:
            code = f.read()

        r = self.client.post("/submit-code", json={"language": "java", "code": code})
        self.assertEqual(r.status_code, 200)
        res = r.json()
        self.assertEqual(res.get("status"), "success")

    def test_upload_file_py(self):
        path = os.path.join(SAMPLES_DIR, "python", "clean_python.py")
        with open(path, "rb") as f:
            r = self.client.post("/upload-file", files={"file": ("clean.py", f, "text/x-python")})

        self.assertEqual(r.status_code, 200)
        res = r.json()
        self.assertEqual(res.get("filename"), "clean.py")
        self.assertEqual(res.get("language"), "Python")
        self.assertEqual(res.get("status"), "Valid Python Syntax")

    def test_upload_file_java(self):
        path = os.path.join(SAMPLES_DIR, "java", "clean_java.java")
        with open(path, "rb") as f:
            r = self.client.post("/upload-file", files={"file": ("Clean.java", f, "text/x-java")})

        self.assertEqual(r.status_code, 200)
        res = r.json()
        self.assertEqual(res.get("filename"), "Clean.java")
        self.assertEqual(res.get("language"), "Java")

    def test_upload_unsupported_file(self):
        r = self.client.post("/upload-file", files={"file": ("sample.txt", b"Hello World", "text/plain")})
        self.assertEqual(r.status_code, 200)
        res = r.json()
        self.assertEqual(res.get("filename"), "sample.txt")
        self.assertEqual(res.get("status"), "Loaded")

    def test_review_code_endpoint(self):
        t0 = time.perf_counter()
        r = self.client.post("/review-code", json={"language": "python", "code": "def foo(): pass\n"})
        elapsed = (time.perf_counter() - t0) * 1000

        self.assertEqual(r.status_code, 200)
        res = r.json()
        self.assertEqual(res.get("status"), "success")
        self.assertIn("summary", res)
        print(f"[PERF] /review-code (Python): {elapsed:.2f} ms")

    def test_chat_endpoint(self):
        t0 = time.perf_counter()
        r = self.client.post("/chat", json={"question": "How do I fix SQL Injection?"})
        elapsed = (time.perf_counter() - t0) * 1000

        self.assertEqual(r.status_code, 200)
        res = r.json()
        self.assertIn("answer", res)
        print(f"[PERF] /chat: {elapsed:.2f} ms")

    def test_failure_handling(self):
        # 422 Validation Error on invalid payload
        r1 = self.client.post("/submit-code", json={"invalid_key": 123})
        self.assertEqual(r1.status_code, 422)
        self.assertEqual(r1.json().get("status"), "error")

        # 404 on missing report download
        r2 = self.client.get("/download-report/non_existent_report_12345.pdf")
        self.assertEqual(r2.status_code, 404)


if __name__ == "__main__":
    unittest.main()
