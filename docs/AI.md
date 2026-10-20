# AI components

**Local LLM.** `backend/app/agent/llm.py` is the only place the app talks to a language model. It is used for STR drafts and case
investigation (`backend/app/agent/investigator.py`, LangGraph). By default it calls a local Ollama server, so nothing leaves the machine.

## Choosing a provider

| `AI_PROVIDER` | Talks to | Settings |
|---|---|---|
| `ollama` (default) | Ollama `/api/chat` | `OLLAMA_URL` (or `AI_BASE_URL`), `OLLAMA_MODEL` (or `AI_MODEL`) |
| `openai_compatible` | any server with `/v1/chat/completions`: vLLM, llama.cpp `llama-server`, LM Studio, a hosted API | `AI_BASE_URL` (ending in `/v1`), `AI_MODEL` (required), `AI_API_KEY` (only if the server needs one) |

Switch by editing `.env` and restarting the API. Calls are logged as `ai_request_*` events with the provider and model but never
the text ([OBSERVABILITY.md](OBSERVABILITY.md)). The API key lives only in the API's `.env`; the React app never receives it.

**External providers are blocked by default.** Case text (already masked by Presidio) goes to the model. If `AI_BASE_URL` is
outside this machine or network (any host that is not `localhost`, `127.0.0.1`, `::1` or a bare Docker/LAN service name), calls
fail unless `AI_ALLOW_EXTERNAL=true`, and then the URL must be `https`. Before enabling a hosted provider, check that your
regulator, your customer contracts and the provider's data terms allow it. Masking reduces, but does not remove, the sensitivity of
what is sent. There is no fallback provider yet: a failed call fails the request.

## Local model setup

`docker compose up -d ollama`, then `docker compose exec ollama ollama pull qwen2.5:14b`. Weights live in the `ollama` volume,
not in Git. A 14B model needs roughly 10 GB of RAM or VRAM at 4-bit quantization (check the model card for your build). For a
lighter development model, set `OLLAMA_MODEL` (or `AI_MODEL`) to a smaller tag you have verified, for example a 3B–7B variant.
Check the model's license on its page before commercial use. Replace a model by pulling it and changing the setting.

Not verified in this environment: no model has been run end to end (K-09), and the `openai_compatible` path is tested against a
stub only (`backend/tests/test_llm_unit.py`), not a real server.

## Safety layers

Presidio masks personal data before text reaches the model (`masking.py`); `guardrails.verify` checks that figures in a draft
match the case data; RAG over reference text uses Chroma (`rag.py`, index built by `backend/scripts/build_rag_index.py`). Drafts are stored
encrypted and need four-eyes approval before filing.

**Detection ML** (not an LLM): XGBoost + SHAP and NetworkX, trained by `backend/scripts/train_and_score.py` from the data in `data/`.
