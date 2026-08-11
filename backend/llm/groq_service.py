import os
import logging
import json
import re
from typing import Optional, Any, Dict

from dotenv import load_dotenv
from openai import (
    OpenAI,
    OpenAIError,
    APIConnectionError,
    APIStatusError,
    APITimeoutError,
)

# ============================================================
# LOAD .ENV
# ============================================================

ROOT_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")
)

ENV_PATH = os.path.join(ROOT_DIR, ".env")

load_dotenv(dotenv_path=ENV_PATH)

logger = logging.getLogger("LLMService")


class GroqService:
    """
    Backward-compatible LLM service.

    IMPORTANT:
    The class name is intentionally kept as GroqService so that
    existing SentinelAI agents do not break.

    The actual LLM provider is now:

        Ollama -> qwen3:8b

    There is NO Groq API call in this implementation.
    """

    _instance: Optional["GroqService"] = None

    def __init__(self):

        # ========================================================
        # OLLAMA CONFIGURATION
        # ========================================================

        self.provider = "ollama"

        self.base_url = os.getenv(
            "OLLAMA_BASE_URL",
            "http://localhost:11434/v1/"
        )

        self.model = os.getenv(
            "OLLAMA_MODEL",
            "qwen3:8b"
        )

        try:
            self.timeout = float(
                os.getenv(
                    "OLLAMA_TIMEOUT",
                    "120.0"
                )
            )
        except ValueError:
            self.timeout = 120.0

        # ========================================================
        # TOKEN LIMITS
        # ========================================================

        self.max_review_tokens = int(
            os.getenv(
                "LLM_MAX_REVIEW_TOKENS",
                "1200"
            )
        )

        self.max_summary_tokens = int(
            os.getenv(
                "LLM_MAX_SUMMARY_TOKENS",
                "600"
            )
        )

        self.max_chat_tokens = int(
            os.getenv(
                "LLM_MAX_CHAT_TOKENS",
                "700"
            )
        )

        # ========================================================
        # OLLAMA OPENAI-COMPATIBLE CLIENT
        # ========================================================

        self.client = OpenAI(
            api_key="ollama",
            base_url=self.base_url,
            timeout=self.timeout,
            max_retries=0,
        )

        logger.info(
            "[LLM] Ollama initialized | model=%s | url=%s",
            self.model,
            self.base_url,
        )

    # ============================================================
    # SINGLETON
    # ============================================================

    @classmethod
    def get_instance(cls) -> "GroqService":

        if cls._instance is None:
            cls._instance = cls()

        return cls._instance

    # ============================================================
    # GENERATE TEXT
    # ============================================================

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.2,
        max_tokens: Optional[int] = None,
        retries: int = 0,
    ) -> str:

        if not prompt or not prompt.strip():
            raise ValueError(
                "LLM prompt cannot be empty."
            )

        if max_tokens is None:
            max_tokens = self.max_review_tokens

        messages = []

        if system_prompt:
            messages.append({
                "role": "system",
                "content": system_prompt
            })

        messages.append({
            "role": "user",
            "content": prompt
        })

        attempts = max(1, retries + 1)

        last_exception = None

        for attempt in range(1, attempts + 1):

            try:

                logger.info(
                    "[LLM] Sending request to Ollama | "
                    "model=%s | attempt=%s/%s",
                    self.model,
                    attempt,
                    attempts
                )

                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    temperature=temperature,
                    max_tokens=max_tokens,

                    # Qwen3 thinking disabled.
                    extra_body={
                        "think": False
                    }
                )

                if not response.choices:
                    raise RuntimeError(
                        "Ollama returned no choices."
                    )

                content = response.choices[0].message.content

                if content is None or not content.strip():
                    raise RuntimeError(
                        "Ollama returned empty response content."
                    )

                return content.strip()

            except (
                APITimeoutError,
                APIConnectionError
            ) as exc:

                last_exception = exc

                logger.warning(
                    "[LLM] Ollama connection/timeout error: %s",
                    exc
                )

                if attempt < attempts:
                    continue

            except APIStatusError as exc:

                last_exception = exc

                logger.error(
                    "[LLM] Ollama HTTP %s: %s",
                    exc.status_code,
                    exc.message
                )

                if exc.status_code >= 500 and attempt < attempts:
                    continue

                break

            except OpenAIError as exc:

                last_exception = exc

                logger.error(
                    "[LLM] Ollama API error: %s",
                    exc
                )

                break

            except Exception as exc:

                last_exception = exc

                logger.exception(
                    "[LLM] Unexpected Ollama error."
                )

                break

        raise RuntimeError(
            "Ollama LLM call failed. "
            f"Details: {last_exception}"
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
    ) -> Dict[str, Any]:

        if max_tokens is None:
            max_tokens = self.max_review_tokens

        json_instruction = """
You MUST return ONLY valid JSON.

Rules:
1. Do not use Markdown.
2. Do not use ```json.
3. Do not add explanations outside the JSON.
4. Use double quotes for JSON keys and string values.
5. Escape double quotes inside strings.
6. The output must be directly parseable by Python json.loads().
"""

        combined_system_prompt = (
            (system_prompt or "")
            + "\n\n"
            + json_instruction
        ).strip()

        raw_text = self.generate(
            prompt=prompt,
            system_prompt=combined_system_prompt,
            temperature=temperature,
            max_tokens=max_tokens
        )

        return self._parse_or_repair_json(raw_text)

    # ============================================================
    # JSON PARSING
    # ============================================================

    def _parse_or_repair_json(
        self,
        raw_text: str
    ) -> Dict[str, Any]:

        clean_text = raw_text.strip()

        # --------------------------------------------------------
        # Remove Markdown fences
        # --------------------------------------------------------

        if clean_text.startswith("```"):

            lines = clean_text.splitlines()

            if lines and lines[0].startswith("```"):
                lines = lines[1:]

            if lines and lines[-1].startswith("```"):
                lines = lines[:-1]

            clean_text = "\n".join(lines).strip()

        # --------------------------------------------------------
        # Direct JSON
        # --------------------------------------------------------

        try:

            parsed = json.loads(
                clean_text,
                strict=False
            )

            if isinstance(parsed, dict):
                return parsed

        except Exception:
            pass

        # --------------------------------------------------------
        # Extract JSON object
        # --------------------------------------------------------

        match = re.search(
            r"\{.*\}",
            clean_text,
            re.DOTALL
        )

        if match:

            try:

                parsed = json.loads(
                    match.group(0),
                    strict=False
                )

                if isinstance(parsed, dict):
                    return parsed

            except Exception:
                pass

        # --------------------------------------------------------
        # Chatbot JSON repair
        # --------------------------------------------------------

        answer_match = re.search(
            r'"answer"\s*:\s*"(.*?)"\s*,\s*'
            r'"related_topics"\s*:\s*(\[.*?\])',
            clean_text,
            re.DOTALL
        )

        if answer_match:

            answer = answer_match.group(1)
            topics_text = answer_match.group(2)

            try:
                topics = json.loads(
                    topics_text,
                    strict=False
                )
            except Exception:
                topics = []

            return {
                "answer": answer,
                "related_topics": topics
            }

        # --------------------------------------------------------
        # Remediation JSON repair
        # --------------------------------------------------------

        fields = [
            "why_it_is_problematic",
            "recommended_fix",
            "corrected_code_example",
            "best_practice",
            "references"
        ]

        positions = {
            field: clean_text.find(f'"{field}":')
            for field in fields
        }

        if all(
            positions[field] != -1
            for field in fields
        ):

            result = {}

            for index, field in enumerate(fields):

                start = (
                    positions[field]
                    + len(f'"{field}":')
                )

                if index + 1 < len(fields):
                    end = positions[fields[index + 1]]
                    value = clean_text[start:end]
                else:
                    value = clean_text[start:]

                value = value.strip().rstrip(",")

                if (
                    value.startswith('"')
                    and value.endswith('"')
                ):
                    value = value[1:-1]

                value = (
                    value
                    .replace("\\n", "\n")
                    .replace('\\"', '"')
                )

                if field == "references":

                    try:
                        result[field] = json.loads(
                            value.rstrip("}").strip()
                        )
                    except Exception:
                        result[field] = []

                else:
                    result[field] = value

            return result

        # --------------------------------------------------------
        # Failed JSON
        # --------------------------------------------------------

        logger.error(
            "[LLM] Could not parse JSON response:\n%s",
            raw_text
        )

        raise ValueError(
            "Invalid JSON returned by Ollama LLM."
        )


# ================================================================
# BACKWARD-COMPATIBLE MODULE ACCESS
# ================================================================

_groq_service_instance = None


def get_groq_service() -> GroqService:

    """
    Existing SentinelAI agents can continue using:

        get_groq_service()

    but the returned service now uses Ollama.
    """

    global _groq_service_instance

    if _groq_service_instance is None:
        _groq_service_instance = (
            GroqService.get_instance()
        )

    return _groq_service_instance


# ================================================================
# MODULE-LEVEL GENERATE
# ================================================================

def generate(
    prompt: str,
    **kwargs
) -> str:

    service = get_groq_service()

    return service.generate(
        prompt,
        **kwargs
    )