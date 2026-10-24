import os
from dotenv import load_dotenv

load_dotenv()

# Development conveniences (Swagger UI, invitation links in API responses, an ephemeral signing key)
# switch on ONLY when ENV=dev is set explicitly. A missing or empty ENV means production.
ENV = os.getenv("ENV") or "production"
IS_DEV = ENV == "dev"

# Access model v2 (memberships, one Platform owner, tenant switching ...). ON by default since the cut-over (phase 9); set ACCESS_MODEL_V2=false only to roll back until the flag is removed;
# both paths must pass the full suite while it exists. Read at request time through config, so tests can switch it.
ACCESS_MODEL_V2 = os.getenv("ACCESS_MODEL_V2", "true").lower() == "true"

# Teams and queues (optional): tenant-defined teams, alerts assignable to a team queue. Off by default; read at request time.
def teams_enabled() -> bool:
    return os.getenv("TEAMS", "false").lower() == "true"


ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY", "")
TRONGRID_API_KEY = os.getenv("TRONGRID_API_KEY", "")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:14b")
# LLM provider: "ollama" (default, uses OLLAMA_URL/OLLAMA_MODEL) or "openai_compatible" (vLLM, llama.cpp server, LM Studio,
# a hosted API ...: AI_BASE_URL ending in /v1, AI_MODEL, AI_API_KEY if the server needs one). Keys stay server-side.
AI_PROVIDER = os.getenv("AI_PROVIDER", "ollama")
AI_BASE_URL = os.getenv("AI_BASE_URL", "")
AI_MODEL = os.getenv("AI_MODEL", "")
AI_API_KEY = os.getenv("AI_API_KEY", "")
# Case text goes to the model (masked first). A provider outside this machine/network is refused unless this is "true".
AI_ALLOW_EXTERNAL = os.getenv("AI_ALLOW_EXTERNAL", "false") == "true"
DATA_DIR = os.getenv("DATA_DIR", "data")
CHROMA_PATH = os.getenv("CHROMA_PATH", f"{DATA_DIR}/chroma")

# Sanctions screening fails closed: without a loaded OFAC list, transfers are held, not released.
# Set OFAC_REQUIRED=false only for an offline demo that relies on data/watchlist.csv.
OFAC_REQUIRED = os.getenv("OFAC_REQUIRED", "true") == "true"
RISK_LIST_TTL_SECONDS = int(os.getenv("RISK_LIST_TTL_SECONDS", str(6 * 3600)))

# USDT contract addresses used for stablecoin tracing
USDT_TRC20 = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
USDT_ERC20 = "0xdAC17F958D2ee523a2206206994597C13D831ec7"

# Score blend weights (rules / ML / graph) and bands
WEIGHTS = {"rules": 0.30, "ml": 0.40, "graph": 0.30}
BANDS = [(71, "high"), (41, "medium"), (0, "low")]
