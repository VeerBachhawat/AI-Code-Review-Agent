import os
import logging
import json
import re
import time
from typing import Optional, Any, Dict
from dotenv import load_dotenv
from openai import OpenAI, OpenAIError, APIConnectionError, APIStatusError, APITimeoutError

# Load .env file explicitly from project root
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
env_path = os.path.join(root_dir, ".env")
if not os.path.exists(env_path):
    env_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".env"))
load_dotenv(dotenv_path=env_path)

logger = logging.getLogger("GroqService")


class GroqService:
    """
    Centralized Groq Service for Llama 3.3 70B LLM interactions using OpenAI-compatible API.
    Enforces server-side API execution, environment-variable loading, retries, and resilient JSON parsing.
    """
    _instance: Optional["GroqService"] = None

    def __init__(self):
        self.api_key = os.getenv("GROQ_API_KEY", "") or os.getenv("XAI_API_KEY", "")
        self.base_url = os.getenv("GROQ_BASE_URL", "") or os.getenv("XAI_BASE_URL", "https://api.groq.com/openai/v1")
        self.model = os.getenv("GROQ_MODEL", "") or os.getenv("XAI_MODEL", "llama-3.3-70b-versatile")
        
        timeout_val = os.getenv("GROQ_TIMEOUT", "") or os.getenv("XAI_TIMEOUT", "30.0")
        try:
            self.timeout = float(timeout_val)
        except ValueError:
            self.timeout = 30.0

        if not self.api_key:
            logger.warning(
                "GROQ_API_KEY environment variable is missing. API calls will fail until configured."
            )

        self.client = OpenAI(
            api_key=self.api_key or "missing_key",
            base_url=self.base_url,
            timeout=self.timeout,
            max_retries=2
        )

    @classmethod
    def get_instance(cls) -> "GroqService":
        if cls._instance is None:
            cls._instance = GroqService()
        return cls._instance

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.2,
        max_tokens: Optional[int] = 2048,
        retries: int = 3
    ) -> str:
        """
        Generate text response from Groq API with retries, timeout, and error handling.
        """
        if not self.api_key or self.api_key == "missing_key":
            raise ValueError("GROQ_API_KEY is missing. Please check your .env configuration.")

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        last_exception = None
        for attempt in range(1, retries + 1):
            try:
                logger.info(f"Sending prompt to Groq LLM ({self.model}), attempt {attempt}/{retries}...")
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    timeout=self.timeout
                )

                content = response.choices[0].message.content
                if content is None:
                    raise ValueError("Received empty response content from Groq API.")

                return content.strip()

            except (APITimeoutError, APIConnectionError) as e:
                logger.warning(f"Groq API network/timeout error (attempt {attempt}/{retries}): {str(e)}")
                last_exception = e
                if attempt < retries:
                    time.sleep(2 ** attempt)
            except APIStatusError as e:
                logger.error(f"Groq API status error HTTP {e.status_code}: {e.message}")
                last_exception = e
                if e.status_code >= 500 and attempt < retries:
                    time.sleep(2 ** attempt)
                else:
                    break
            except OpenAIError as e:
                logger.error(f"OpenAI client error interacting with Groq API: {str(e)}")
                last_exception = e
                break
            except Exception as e:
                logger.error(f"Unexpected error calling Groq API: {str(e)}")
                last_exception = e
                break

        raise RuntimeError(f"Groq API call failed after {retries} attempts. Details: {str(last_exception)}")

    def generate_json(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.1,
        max_tokens: Optional[int] = 2048
    ) -> Dict[str, Any]:
        """
        Generate structured JSON response, automatically handling markdown fences and parsing issues.
        Includes resilient JSON repair for LLM-generated strings containing unescaped quotes.
        """
        json_system_prompt = (system_prompt or "") + "\nCRITICAL: Return valid JSON ONLY. Escape all double quotes inside string fields with backslashes."

        raw_text = self.generate(
            prompt=prompt,
            system_prompt=json_system_prompt.strip(),
            temperature=temperature,
            max_tokens=max_tokens
        )

        return self._parse_or_repair_json(raw_text)

    def _parse_or_repair_json(self, raw_text: str) -> Dict[str, Any]:
        clean_text = raw_text.strip()
        if clean_text.startswith("```"):
            lines = clean_text.splitlines()
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].startswith("```"):
                lines = lines[:-1]
            clean_text = "\n".join(lines).strip()

        # 1. Direct standard JSON parsing
        try:
            return json.loads(clean_text, strict=False)
        except Exception:
            pass

        # 2. Extract JSON block using regex if wrapped in text
        match = re.search(r'\{.*\}', clean_text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0), strict=False)
            except Exception:
                pass

        # 3. Structural repair for Conversational Assistant {"answer": ..., "related_topics": ...}
        ans_match = re.search(r'"answer"\s*:\s*"(.*?)"\s*,\s*"related_topics"\s*:\s*(\[.*?\])', clean_text, re.DOTALL)
        if ans_match:
            raw_ans = ans_match.group(1)
            raw_topics = ans_match.group(2)
            try:
                topics = json.loads(raw_topics, strict=False)
            except Exception:
                topics = ["Code Analysis", "Security Best Practices", "Software Refactoring"]
            return {"answer": raw_ans, "related_topics": topics}

        # 4. Structural repair for Remediation Agent using index splitting
        why_idx = clean_text.find('"why_it_is_problematic":')
        rec_idx = clean_text.find('"recommended_fix":')
        cor_idx = clean_text.find('"corrected_code_example":')
        best_idx = clean_text.find('"best_practice":')
        ref_idx = clean_text.find('"references":')

        if why_idx != -1 and rec_idx > why_idx and cor_idx > rec_idx and best_idx > cor_idx and ref_idx > best_idx:
            why_raw = clean_text[why_idx + len('"why_it_is_problematic":') : rec_idx].strip()
            rec_raw = clean_text[rec_idx + len('"recommended_fix":') : cor_idx].strip()
            cor_raw = clean_text[cor_idx + len('"corrected_code_example":') : best_idx].strip()
            best_raw = clean_text[best_idx + len('"best_practice":') : ref_idx].strip()
            ref_raw = clean_text[ref_idx + len('"references":') :].strip()

            def clean_val(v: str) -> str:
                v = v.rstrip(',').strip()
                if v.startswith('"') and v.endswith('"'):
                    v = v[1:-1]
                return v.replace('\\n', '\n').replace('\\"', '"')

            try:
                refs = json.loads(ref_raw.rstrip('}').strip(), strict=False)
            except Exception:
                refs = ["OWASP Security Guidelines", "CWE Vulnerability Index"]

            return {
                "why_it_is_problematic": clean_val(why_raw),
                "recommended_fix": clean_val(rec_raw),
                "corrected_code_example": clean_val(cor_raw),
                "best_practice": clean_val(best_raw),
                "references": refs if isinstance(refs, list) else [str(refs)]
            }

        logger.error(f"Failed to parse JSON from Groq response. Raw output:\n{raw_text}")
        raise ValueError(f"Invalid JSON returned by Groq LLM.")


_groq_service_instance = None


def get_groq_service() -> GroqService:
    global _groq_service_instance
    if _groq_service_instance is None:
        _groq_service_instance = GroqService()
    return _groq_service_instance


def generate(prompt: str, **kwargs) -> str:
    """
    Module-level generate function.
    """
    service = get_groq_service()
    return service.generate(prompt, **kwargs)
