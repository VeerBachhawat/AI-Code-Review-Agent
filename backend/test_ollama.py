import sys
import os

root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from backend.llm.ollama_service import ollama_service, get_ollama_service


def test_ollama_properties():
    print("--- 1. Testing Ollama Service Properties ---")
    service = get_ollama_service()
    assert service.provider == "ollama", f"Expected provider 'ollama', got '{service.provider}'"
    assert service.model == "qwen3:8b", f"Expected model 'qwen3:8b', got '{service.model}'"
    print(f"[OK] Provider: {service.provider}")
    print(f"[OK] Model: {service.model}")
    print(f"[OK] Base URL: {service.base_url}")


def test_ollama_health_check():
    print("\n--- 2. Testing Ollama Health Check ---")
    health = ollama_service.health_check()
    print(f"Health check response: {health}")
    assert health.get("status") == "connected", f"Ollama health status failed: {health}"
    assert health.get("model_available") is True, f"Model qwen3:8b not available in Ollama"
    print("[OK] Health check PASSED!")


def test_ollama_text_generation():
    print("\n--- 3. Testing Text Generation ---")
    prompt = "Explain SQL Injection in exactly two sentences."
    system_prompt = "You are a cybersecurity expert. Be extremely concise."
    
    response = ollama_service.generate(
        system_prompt=system_prompt,
        user_prompt=prompt,
        max_tokens=500,
        temperature=0.2
    )
    print(f"Generated text:\n{response}")
    assert len(response) > 10, "Response is too short or empty"
    print("[OK] Text generation PASSED!")


def test_ollama_json_generation():
    print("\n--- 4. Testing JSON Generation ---")
    prompt = "Return JSON with exactly these keys: answer, severity. The answer should explain SQL injection and severity should be High."
    system_prompt = "You are a secure coding auditor. Output valid JSON only."
    
    data = ollama_service.generate_json(
        prompt=prompt,
        system_prompt=system_prompt,
        temperature=0.1,
        max_tokens=300
    )
    print(f"Generated JSON object: {data}")
    assert isinstance(data, dict), "Result is not a dict"
    assert "answer" in data, "Missing 'answer' key in JSON"
    assert "severity" in data, "Missing 'severity' key in JSON"
    print("[OK] JSON generation PASSED!")


if __name__ == "__main__":
    try:
        test_ollama_properties()
        test_ollama_health_check()
        test_ollama_text_generation()
        test_ollama_json_generation()
        print("\nALL OLLAMA TESTS PASSED SUCCESSFULLY!")
    except Exception as e:
        print(f"\nOLLAMA TEST FAILED: {e}")
        sys.exit(1)
