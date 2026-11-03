"""Minimal Anthropic Messages API client on stdlib ``urllib`` (no new dependency).

* The API key comes from the ``ANTHROPIC_API_KEY`` environment variable ONLY - never a file,
  never a CLI flag, never logged, never part of an error message.
* No sampling parameters are sent (newer models reject non-default ``temperature``/``top_p``);
  determinism is not expected from the model - it is enforced downstream by validation, the
  cache, and freezing the drafted overlay.
* Output format is requested in the prompt and validated strictly by the caller, rather than
  relying on forced tool use / structured-output parameters whose support varies by model.

The client is a plain callable so tests inject a fake with the same signature.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from typing import Callable

API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"
DEFAULT_MODEL = "claude-haiku-5-5"
"""Fast/cheap default. Override with ``classify --model``."""
API_KEY_ENV = "ANTHROPIC_API_KEY"

LLM = Callable[..., str]
"""``llm(model=..., system=..., user=..., max_tokens=...) -> response text``."""

_RETRY_STATUS = {408, 409, 429, 500, 502, 503, 504, 529}
_EFFORT_MODELS = re.compile(r"^claude-(haiku|sonnet|opus|fable|mythos)-5")  # `effort` is a 5.x feature


class LLMError(RuntimeError):
    """A failed or unusable API call. Messages never contain the API key."""


class MissingApiKey(LLMError):
    """``ANTHROPIC_API_KEY`` is not set."""


def api_key_from_env(env: dict[str, str] | None = None) -> str | None:
    key = (os.environ if env is None else env).get(API_KEY_ENV, "").strip()
    return key or None


class AnthropicHTTP:
    """``POST /v1/messages`` with retry on 429/5xx/connection errors."""

    def __init__(
        self,
        api_key: str,
        *,
        url: str = API_URL,
        timeout: float = 120.0,
        retries: int = 2,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not api_key:
            raise MissingApiKey(f"{API_KEY_ENV} is not set")
        self._key = api_key
        self._url = url
        self._timeout = timeout
        self._retries = retries
        self._sleep = sleep

    def __repr__(self) -> str:  # never leak the key through a stray print/log
        return "AnthropicHTTP(<key hidden>)"

    def __call__(self, *, model: str, system: str, user: str, max_tokens: int = 8000) -> str:
        body: dict = {
            "model": model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        if _EFFORT_MODELS.match(model):
            body["output_config"] = {"effort": "low"}  # classification needs little reasoning
        payload = json.dumps(body).encode("utf-8")
        headers = {
            "content-type": "application/json",
            "x-api-key": self._key,
            "anthropic-version": ANTHROPIC_VERSION,
        }
        last: str = "no attempt made"
        for attempt in range(self._retries + 1):
            req = urllib.request.Request(self._url, data=payload, headers=headers, method="POST")
            wait = 2.0 * (attempt + 1)
            try:
                with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # noqa: S310 - fixed https URL
                    return _text_of(json.load(resp))
            except urllib.error.HTTPError as e:
                detail = _error_detail(e)
                last = f"HTTP {e.code}: {detail}"
                if e.code not in _RETRY_STATUS:
                    raise LLMError(last) from None
                retry_after = e.headers.get("retry-after") if e.headers else None
                if retry_after and retry_after.isdigit():
                    wait = min(float(retry_after), 60.0)
            except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
                last = f"connection error: {type(e).__name__}"
            except ValueError:
                raise LLMError("API returned a non-JSON response") from None
            if attempt < self._retries:
                self._sleep(wait)
        raise LLMError(f"API call failed after {self._retries + 1} attempt(s) ({last})")


def _error_detail(e: urllib.error.HTTPError) -> str:
    try:
        data = json.loads(e.read().decode("utf-8", "replace"))
        msg = data.get("error", {}).get("message") or ""
    except Exception:  # noqa: BLE001 - best-effort diagnostics only
        msg = ""
    return (msg or str(e.reason))[:300]


def _text_of(message: object) -> str:
    """Concatenate the text blocks of a Messages API response (thinking blocks are skipped)."""
    if not isinstance(message, dict):
        raise LLMError("unexpected API response shape")
    if message.get("stop_reason") == "refusal":
        raise LLMError("the model declined the request (stop_reason=refusal)")
    blocks = message.get("content")
    if not isinstance(blocks, list):
        raise LLMError("unexpected API response shape (no content list)")
    return "".join(
        b.get("text", "") for b in blocks if isinstance(b, dict) and b.get("type") == "text"
    )
