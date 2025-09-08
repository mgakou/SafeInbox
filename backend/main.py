import os
import time
import hmac
import hashlib
import requests
from typing import Optional, Literal

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

# -- Load env
load_dotenv()
OPENAI_KEY = os.getenv("OPENAI_API_KEY", "")
ABUSECH_KEY = os.getenv("ABUSECH_API_KEY", "")
DEV_SHARED_TOKEN = os.getenv("DEV_SHARED_TOKEN", "")

if not OPENAI_KEY:
    print("[WARN] OPENAI_API_KEY manquant dans backend/.env")

# -- App & CORS (dev): accepte localhost et extension
app = FastAPI(title="Phisher Dev Backend")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],           # dev : permissif (chrome-extension://*)
    allow_credentials=False,
    allow_methods=["POST", "OPTIONS"],
    allow_headers=["*"],
)

# -- Rate limit (simple, mémoire)
limiter = Limiter(key_func=get_remote_address, default_limits=["60/minute"])
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

@app.exception_handler(RateLimitExceeded)
def ratelimit_handler(request: Request, exc: RateLimitExceeded):
    return HTTPException(status_code=429, detail="Too many requests")

# -- Models
Provider = Literal["openai", "abusech"]
class AnalyzeReq(BaseModel):
    provider: Provider = "openai"
    prompt: Optional[str] = None         # pour OpenAI
    url: Optional[str] = None            # pour Abuse.ch/url scan
    minimal: bool = True                 # RGPD: n’envoyer que le strict nécessaire

def verify_dev_token(dev_token: Optional[str]):
    if not DEV_SHARED_TOKEN:
        return
    if not dev_token or not hmac.compare_digest(dev_token, DEV_SHARED_TOKEN):
        raise HTTPException(status_code=401, detail="Unauthorized")

# -- Helpers : appels providers
def call_openai_chat(prompt: str):
    url = "https://api.openai.com/v1/chat/completions"
    headers = {"Authorization": f"Bearer {OPENAI_KEY}", "Content-Type": "application/json"}
    payload = {
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.0,
    }
    r = requests.post(url, headers=headers, json=payload, timeout=30)
    return r.json(), r.status_code

def call_abusech_url(url_to_check: str):
    # Exemple d'appel à l'API Abuse.ch (URLhaus)
    # Abuse.ch attend généralement une requête POST avec l'URL à vérifier
    # Documentation: https://urlhaus-api.abuse.ch/
    api_url = "https://urlhaus-api.abuse.ch/v1/url/"
    payload = {"url": url_to_check}
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    r = requests.post(api_url, data=payload, headers=headers, timeout=30)
    return r.json(), r.status_code

# -- Route principale
@app.post("/api/analyze")
@limiter.limit("30/minute")
def analyze(req: AnalyzeReq, request: Request, x_dev_token: Optional[str] = Header(None)):
    # Auth dev légère (optionnelle, mais utile si tu diffuses l’extension à d’autres)
    verify_dev_token(x_dev_token)

    start = time.time()
    try:
        if req.provider == "openai":
            if not req.prompt:
                raise HTTPException(status_code=400, detail="prompt required for openai")
            if not OPENAI_KEY:
                raise HTTPException(status_code=500, detail="OPENAI_API_KEY missing")
            # RGPD minimalisme : en dev, on envoie que le prompt fourni déjà filtré côté extension
            body, code = call_openai_chat(req.prompt)

        elif req.provider == "abusech":
            if not req.url:
                raise HTTPException(status_code=400, detail="url required for abusech")
            if not ABUSECH_KEY:
                raise HTTPException(status_code=500, detail="ABUSECH_API_KEY missing")
            body, code = call_abusech_url(req.url)

        else:
            raise HTTPException(status_code=400, detail="unknown provider")

        elapsed = round(time.time() - start, 3)
        return {"ok": code < 400, "provider": req.provider, "elapsed": elapsed, "data": body}

    except HTTPException:
        raise
    except Exception as e:
        # Ne jamais logger de secrets; message neutre
        raise HTTPException(status_code=500, detail="backend_error") from e