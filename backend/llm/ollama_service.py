import os
import logging
from typing import Optional

import requests
from dotenv import load_dotenv
from openai import OpenAI


# Load environment variables from .env
load_dotenv()

logger = logging.getLogger(__name__)


class OllamaService:
    """
    Centralized Ollama LLM service for SentinelAI.

    This service handles:
    - Code review
    - PR summaries
    - Chatbot responses
    - Ollama health checks
    """

    def __init__(self):
        self.provider = "ollama"

        self.base_url = os.getenv(
            "OLLAMA_BASE_URL",
            "http://localhost:11434/v1/"
        )

        self.model = os.getenv(
            "OLLAMA_MODEL",
            "qwen3:8b"
        )

        self.timeout = float(
            os.getenv(
                "OLLAMA_TIMEOUT",
                "300.0"
            )
        )

        self.max_review_tokens = int(
            os.getenv(
                "LLM_MAX_REVIEW_TOKENS",
                "600"
            )
        )

        self.max_summary_tokens = int(
            os.getenv(
                "LLM_MAX_SUMMARY_TOKENS",
                "250"
            )
        )

        self.max_chat_tokens = int(
            os.getenv(
                "LLM_MAX_CHAT_TOKENS",
                "400"
            )
        )

        self.call_count = 0

        # Ollama provides an OpenAI-compatible API.
        self.client = OpenAI(
            base_url=self.base_url,
            api_key="ollama",
            timeout=self.timeout
        )

        logger.info(
            "[OLLAMA] Initialized | model=%s | url=%s",
            self.model,
            self.base_url
        )

    def reset_call_count(self) -> int:
        count = self.call_count
        self.call_count = 0
        return count

    # ============================================================
    # GENERIC LLM GENERATION
    # ============================================================

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: Optional[int] = None,
        temperature: float = 0.2
    ) -> str:

        if max_tokens is None:
            max_tokens = self.max_review_tokens

        self.call_count += 1
        request_id = self.call_count
        logger.info("[OLLAMA] Request #%d | max_tokens=%d | temp=%.2f", request_id, max_tokens, temperature)

        try:
            response = self.client.chat.completions.create(
                model=self.model,

                messages=[
                    {
                        "role": "system",
                        "content": system_prompt
                    },
                    {
                        "role": "user",
                        "content": user_prompt
                    }
                ],

                temperature=temperature,
                max_tokens=max_tokens,

                # Disable Qwen3 thinking output.
                extra_body={
                    "think": False
                }
            )

            if not response.choices:
                raise RuntimeError(
                    "Ollama returned no choices."
                )

            choice = response.choices[0]
            finish_reason = getattr(choice, "finish_reason", "unknown")
            content = choice.message.content

            logger.info(
                "[OLLAMA] Completion received | finish_reason=%s | length=%s",
                finish_reason,
                len(content) if content else 0
            )

            if not content:
                raise RuntimeError(
                    f"Ollama returned an empty response (finish_reason='{finish_reason}')."
                )

            return content.strip()

        except Exception as exc:
            logger.exception(
                "[OLLAMA] Generation failed: %s",
                exc
            )

            raise RuntimeError(
                f"Ollama LLM generation failed: {exc}"
            ) from exc

    # ============================================================
    # CODE REVIEW
    # ============================================================

    def generate_review(
        self,
        system_prompt: str,
        user_prompt: str
    ) -> str:

        return self.generate(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_tokens=self.max_review_tokens,
            temperature=0.2
        )

    # ============================================================
    # PR SUMMARY
    # ============================================================

    def generate_summary(
        self,
        system_prompt: str,
        user_prompt: str
    ) -> str:

        return self.generate(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_tokens=self.max_summary_tokens,
            temperature=0.2
        )

    # ============================================================
    # CHATBOT
    # ============================================================

    def generate_chat(
        self,
        system_prompt: str,
        user_prompt: str
    ) -> str:

        return self.generate(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_tokens=self.max_chat_tokens,
            temperature=0.3
        )

    # ============================================================
    # JSON GENERATION
    # ============================================================

    def generate_json(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.1,
        max_tokens: Optional[int] = None
    ) -> dict:

        json_instruction = (
            "You MUST return ONLY valid JSON.\n"
            "Rules:\n"
            "1. Do not use Markdown formatting or ```json.\n"
            "2. Use double quotes for JSON keys and values.\n"
            "3. Return directly parseable JSON object."
        )

        combined_system = (
            (system_prompt or "")
            + "\n\n"
            + json_instruction
        ).strip()

        raw_text = self.generate(
            system_prompt=combined_system,
            user_prompt=prompt,
            max_tokens=max_tokens or self.max_review_tokens,
            temperature=temperature
        )

        return self._parse_json(raw_text)

    def _parse_json(self, raw_text: str) -> dict:
        import json
        import re

        clean_text = raw_text.strip()

        # Remove Qwen3 thinking tags if present
        if "</think>" in clean_text:
            clean_text = clean_text.split("</think>")[-1].strip()

        if clean_text.startswith("```"):
            lines = clean_text.splitlines()
            if lines and lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].startswith("```"):
                lines = lines[:-1]
            clean_text = "\n".join(lines).strip()

        try:
            parsed = json.loads(clean_text, strict=False)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass

        # Search for first { and last }
        match = re.search(r"\{.*\}", clean_text, re.DOTALL)
        if match:
            candidate = match.group(0)
            try:
                parsed = json.loads(candidate, strict=False)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                pass

            # Try ast.literal_eval as fallback for single quotes or Python dict formats
            try:
                import ast
                parsed = ast.literal_eval(candidate)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                pass

        raise ValueError(f"Could not parse valid JSON from Ollama response: {raw_text}")

    # ============================================================
    # HEALTH CHECK
    # ============================================================

    def health_check(self) -> dict:
        """
        Check whether Ollama is reachable and the configured
        model exists.

        This uses Ollama's /api/tags endpoint instead of
        generating an unnecessary LLM response.
        """

        try:
            response = requests.get(
                "http://localhost:11434/api/tags",
                timeout=10
            )

            response.raise_for_status()

            data = response.json()

            models = [
                model.get("name", "")
                for model in data.get("models", [])
            ]

            model_available = any(
                name == self.model
                or name.startswith(
                    self.model.split(":")[0] + ":"
                )
                for name in models
            )

            if not model_available:
                return {
                    "status": "error",
                    "provider": "ollama",
                    "model": self.model,
                    "model_available": False,
                    "error": (
                        f"Model '{self.model}' is not installed. "
                        f"Available models: {models}"
                    )
                }

            return {
                "status": "connected",
                "provider": "ollama",
                "model": self.model,
                "ollama_url": "http://localhost:11434",
                "model_available": True
            }

        except Exception as exc:
            logger.exception(
                "[OLLAMA] Health check failed: %s",
                exc
            )

            return {
                "status": "error",
                "provider": "ollama",
                "model": self.model,
                "model_available": False,
                "error": str(exc)
            }


# ================================================================
# SHARED SERVICE INSTANCE & ACCESSOR
# ================================================================

ollama_service = OllamaService()


def get_ollama_service() -> OllamaService:
    """Returns the singleton instance of OllamaService."""
    return ollama_service