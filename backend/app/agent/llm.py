"""LLM client with a provider switch (AI_PROVIDER): local Ollama by default, or any OpenAI-compatible server.

Case text is masked (Presidio) before it gets here, but a provider outside this machine or network still receives it, so
it is refused unless AI_ALLOW_EXTERNAL=true and the URL is https. API keys are server-side only and never logged."""
import httpx
import logging
import time
from urllib.parse import urlparse
from app import config

log = logging.getLogger("sentrail.ai")
PROVIDERS = ("ollama", "openai_compatible")


def _is_local(url: str) -> bool:
    host = urlparse(url).hostname or ""
    return host in ("localhost", "127.0.0.1", "::1") or "." not in host      # a bare name is a Docker/LAN service


def settings() -> dict:
    """Resolve and validate the provider settings (read at call time)."""
    provider = config.AI_PROVIDER
    if provider == "ollama":
        return {"provider": provider, "model": config.AI_MODEL or config.OLLAMA_MODEL,
                "base_url": (config.AI_BASE_URL or config.OLLAMA_URL).rstrip("/"), "api_key": ""}
    if provider != "openai_compatible":
        raise RuntimeError(f"AI_PROVIDER must be one of {', '.join(PROVIDERS)}")
    if not config.AI_BASE_URL or not config.AI_MODEL:
        raise RuntimeError("AI_PROVIDER=openai_compatible needs AI_BASE_URL and AI_MODEL")
    if not _is_local(config.AI_BASE_URL):
        if not config.AI_ALLOW_EXTERNAL:
            raise RuntimeError("AI_BASE_URL is outside this machine/network: set AI_ALLOW_EXTERNAL=true to allow case text to leave it")
        if urlparse(config.AI_BASE_URL).scheme != "https":
            raise RuntimeError("An external AI_BASE_URL must use https")
    return {"provider": provider, "model": config.AI_MODEL, "base_url": config.AI_BASE_URL.rstrip("/"), "api_key": config.AI_API_KEY}


def chat(system: str, user: str, temperature: float = 0.1) -> str:
    """One LLM call. Logs ai_request_completed/ai_request_failed with sizes and timing, never the text."""
    start = time.perf_counter()
    meta = {"provider": config.AI_PROVIDER, "model": config.AI_MODEL or config.OLLAMA_MODEL, "input_chars": len(system) + len(user)}
    try:
        cfg = settings()
        meta.update(provider=cfg["provider"], model=cfg["model"])
        log.info("ai request started", extra={"event": "ai_request_started", **meta})
        out = _call[cfg["provider"]](cfg, system, user, temperature)
    except Exception as exc:
        log.warning("ai request failed", extra={"event": "ai_request_failed", "success": False,
                    "error_category": type(exc).__name__, "duration_ms": round((time.perf_counter() - start) * 1000, 1), **meta})
        raise
    log.info("ai request completed", extra={"event": "ai_request_completed", "success": True, "output_chars": len(out),
             "duration_ms": round((time.perf_counter() - start) * 1000, 1), **meta})
    return out


def _ollama(cfg: dict, system: str, user: str, temperature: float) -> str:
    r = httpx.post(f"{cfg['base_url']}/api/chat", timeout=180, json={
        "model": cfg["model"], "stream": False,
        "options": {"temperature": temperature},
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]})
    r.raise_for_status()
    return r.json()["message"]["content"].strip()


def _openai_compatible(cfg: dict, system: str, user: str, temperature: float) -> str:
    headers = {"Authorization": f"Bearer {cfg['api_key']}"} if cfg["api_key"] else {}
    r = httpx.post(f"{cfg['base_url']}/chat/completions", timeout=180, headers=headers, json={
        "model": cfg["model"], "temperature": temperature, "stream": False,
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]})
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"].strip()


_call = {"ollama": _ollama, "openai_compatible": _openai_compatible}
