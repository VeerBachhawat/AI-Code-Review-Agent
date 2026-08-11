import os
import sys
import logging

# Ensure project root directory is in sys.path
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from dotenv import load_dotenv

# Load .env file from project root
dotenv_path = os.path.join(root_dir, ".env")
load_dotenv(dotenv_path=dotenv_path)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("GroqDiagnostic")

print("==================================================")
print("GROQ DIAGNOSTIC TEST")
print("==================================================")

api_key = os.getenv("GROQ_API_KEY") or os.getenv("XAI_API_KEY")
model = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
base_url = os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
timeout = os.getenv("GROQ_TIMEOUT", "30.0")

has_key = bool(api_key and api_key.strip())
key_prefix = api_key[:4] + "***" if has_key and len(api_key) > 4 else "None"

print(f"[GROQ CONFIG]")
print(f"  API Key Configured: {has_key}")
print(f"  API Key Prefix:     {key_prefix}")
print(f"  Model:               {model}")
print(f"  Base URL:            {base_url}")
print(f"  Timeout:             {timeout}")
print("==================================================")

try:
    from backend.llm.groq_service import get_groq_service
    service = get_groq_service()
    print("[TESTING GROQ SERVICE INSTANTIATION] Success!")

    print("[SENDING TEST QUESTION TO GROQ API] ...")
    response = service.generate("Reply with exactly: GROQ CONNECTION OK", system_prompt="Test Assistant")
    print(f"[GROQ API RESPONSE SUCCESS!]")
    print(f"Response text: '{response}'")

except Exception as e:
    print("[GROQ API CALL FAILED WITH EXCEPTION]:")
    import traceback
    traceback.print_exc()
    sys.exit(1)
