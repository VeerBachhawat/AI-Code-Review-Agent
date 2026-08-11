from llm.ollama_service import ollama_service


print("=" * 60)
print("SENTINELAI OLLAMA SERVICE TEST")
print("=" * 60)

print("Provider:", ollama_service.provider)
print("Model:", ollama_service.model)
print("Base URL:", ollama_service.base_url)

print("\nTesting LLM generation...\n")

answer = ollama_service.generate(
    system_prompt="""
You are SentinelAI, an expert application security assistant.

Give concise and technically accurate answers.
Do not provide unnecessary explanations.
""",

    user_prompt="""
Explain SQL Injection in simple terms.
Also explain the recommended secure fix.
""",

    max_tokens=300,

    temperature=0.2
)

print("===== LLM RESPONSE =====")
print(answer)

print("\n===== HEALTH CHECK =====")

health = ollama_service.health_check()

print(health)