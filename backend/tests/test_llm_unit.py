"""LLM provider switch: request shapes, validation, the external-provider guard. No database, no network."""
import sys
sys.path.insert(0, ".")
from app import config
from app.agent import llm

ok = True


def check(name, cond):
    global ok
    ok &= bool(cond)
    print(("PASS" if cond else "FAIL"), name)


sent = {}


class R:
    def __init__(self, body): self.body = body
    def raise_for_status(self): pass
    def json(self): return self.body


def fake_post(url, **kw):
    sent.clear()
    sent.update(url=url, **kw)
    return R({"message": {"content": " ollama says hi "}} if url.endswith("/api/chat")
             else {"choices": [{"message": {"content": " compat says hi "}}]})


llm.httpx.post = fake_post


def setup(**kw):
    for k, v in dict(AI_PROVIDER="ollama", AI_BASE_URL="", AI_MODEL="", AI_API_KEY="", AI_ALLOW_EXTERNAL=False,
                     OLLAMA_URL="http://localhost:11434", OLLAMA_MODEL="qwen2.5:14b").items():
        setattr(config, k, kw.get(k, v))


def fails(**kw):
    setup(**kw)
    try:
        llm.chat("s", "u")
        return None
    except RuntimeError as e:
        return str(e)


setup()
check("default is Ollama with the old OLLAMA_* settings", llm.chat("s", "u") == "ollama says hi"
      and sent["url"] == "http://localhost:11434/api/chat" and sent["json"]["model"] == "qwen2.5:14b")
setup(AI_MODEL="llama3.2:3b")
llm.chat("s", "u")
check("AI_MODEL overrides OLLAMA_MODEL", sent["json"]["model"] == "llama3.2:3b")

setup(AI_PROVIDER="openai_compatible", AI_BASE_URL="http://localhost:8001/v1/", AI_MODEL="qwen2.5-7b", AI_API_KEY="k-123")
check("openai_compatible: /chat/completions, bearer key, parsed reply", llm.chat("s", "u") == "compat says hi"
      and sent["url"] == "http://localhost:8001/v1/chat/completions" and sent["headers"] == {"Authorization": "Bearer k-123"}
      and sent["json"]["model"] == "qwen2.5-7b" and sent["json"]["messages"][0]["role"] == "system")
setup(AI_PROVIDER="openai_compatible", AI_BASE_URL="http://vllm:8000/v1", AI_MODEL="m")
llm.chat("s", "u")
check("no key means no Authorization header; a bare service name counts as local", sent["headers"] == {})

check("unknown provider rejected", "AI_PROVIDER must be" in (fails(AI_PROVIDER="bogus") or ""))
check("openai_compatible needs url and model",
      "needs AI_BASE_URL and AI_MODEL" in (fails(AI_PROVIDER="openai_compatible", AI_MODEL="m") or ""))
check("external provider refused by default",
      "AI_ALLOW_EXTERNAL" in (fails(AI_PROVIDER="openai_compatible", AI_BASE_URL="https://api.example.com/v1", AI_MODEL="m") or ""))
check("external provider needs https even when allowed",
      "https" in (fails(AI_PROVIDER="openai_compatible", AI_BASE_URL="http://api.example.com/v1", AI_MODEL="m",
                        AI_ALLOW_EXTERNAL=True) or ""))
setup(AI_PROVIDER="openai_compatible", AI_BASE_URL="https://api.example.com/v1", AI_MODEL="m", AI_ALLOW_EXTERNAL=True, AI_API_KEY="k")
check("external https provider works when explicitly allowed", llm.chat("s", "u") == "compat says hi")
sys.exit(0 if ok else 1)
