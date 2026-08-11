import logging
from typing import Optional, Any, Dict

try:
    from llm.groq_service import GroqService, get_groq_service
except ImportError:
    from backend.llm.groq_service import GroqService, get_groq_service

logger = logging.getLogger(__name__)

# Backward compatibility alias for GrokClient -> GroqService
GrokClient = GroqService

def get_grok_client() -> GroqService:
    """
    Alias returning the centralized GroqService instance.
    """
    return get_groq_service()

def generate(prompt: str, **kwargs) -> str:
    """
    Exposed module function.
    """
    client = get_grok_client()
    return client.generate(prompt, **kwargs)
