import os
import re
import ipaddress
import asyncio
import socket
import httpx
from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel
from bs4 import BeautifulSoup
from supabase import create_client, Client

app = FastAPI(title="Anti-Synthetic Corporate KYC API")

# Caricamento credenziali dalle variabili d'ambiente
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
RAPIDAPI_SECRET = os.getenv("RAPIDAPI_PROXY_SECRET")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Impronte linguistiche tipiche dei testi aziendali generati da LLM (ChatGPT/Claude)
AI_MARKETING_CLICHES = [
    r"in today's fast-paced", r"digital landscape", r"cutting-edge solutions",
    r"revolutionize the way", r"delivering unparalleled", r"at our core",
    r"testament to our commitment", r"foster a collaborative", r"beacon of innovation",
    r"elevate your business", r"seamless integration"
]

class KYCRequest(BaseModel):
    url: str

# Protezione di rete avanzata contro SSRF e DNS Rebinding (Corretta con moduli nativi)
class PinnedIPTransport(httpx.AsyncHTTPTransport):
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        url = request.url
        hostname = url.host
        
        loop = asyncio.get_running_loop()
        try:
            # Risoluzione DNS nativa e asincrona
            addr_info = await loop.getaddrinfo(
                hostname, 
                url.port or (443 if url.scheme == "https" else 80), 
                proto=socket.IPPROTO_TCP
            )
            target_ip = addr_info[0][4][0]
        except Exception:
            raise httpx.ConnectError("Impossibile risolvere il DNS dell'URL.")
        
        # Controllo IP Privati/Locali (Blocco SSRF)
        ip_obj = ipaddress.ip_address(target_ip)
        if ip_obj.is_private or ip_obj.is_loopback:
            raise httpx.ConnectError("Accesso negato: Vulnerabilità SSRF bloccata.")
        
        # Pinning dell'IP contro DNS Rebinding
        request.extensions["sni_hostname"] = hostname
        request.url = request.url.copy_with(host=target_ip)
        request.headers["Host"] = hostname
        
        return await super().handle_async_request(request)

async def verify_rapidapi_gate(x_rapidapi_proxy_secret: str = Header(None)):
    if not RAPIDAPI_SECRET:
        return
    if x_rapidapi_proxy_secret != RAPIDAPI_SECRET:
        raise HTTPException(status_code=401, detail="Richiesta non autorizzata. Passa dal gateway di RapidAPI.")

@app.get("/")
def health():
    return {"status": "healthy", "engine": "TrustShield KYC V1"}

@app.post("/verify")
async def verify_company(payload: KYCRequest, _ = Depends(verify_rapidapi_gate)):
    target_url = str(payload.url).strip()
    
    # 1. Controllo Cache atomica
    try:
        cached = supabase.table("kyc_verifications").select("*").eq("url", target_url).execute()
        if cached.data:
            rec = cached.data[0]
            return {
                "status": "success",
                "source": "cache",
                "target_url": target_url,
                "corporate_trust_score": rec["trust_score"],
                "risk_level": rec["risk_level"],
                "analysis": {
                    "ai_text_probability": f"{rec['ai_text_probability']}%",
                    "dead_or_placeholder_links": rec["broken_links_count"]
                }
            }
    except Exception:
        pass

    # 2. Scraping Sicuro in Streaming
    try:
        transport = PinnedIPTransport(verify=True)
        async with httpx.AsyncClient(transport=transport, timeout=12.0, follow_redirects=False) as client:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            async with client.stream("GET", target_url, headers=headers) as response:
                if response.status_code != 200:
                    raise HTTPException(status_code=400, detail=f"Sito non verificabile. Status code: {response.status_code}")
                
                chunks = []
                size = 0
                async for chunk in response.aiter_bytes(chunk_size=8192):
                    chunks.append(chunk)
                    size += len(chunk)
                    if size > 3 * 1024 * 1024: # Taglio di sicurezza a 3MB
                        raise HTTPException(status_code=413, detail="Pagina troppo pesante per gli standard KYC aziendali.")
                
                html = b"".join(chunks).decode("utf-8", errors="ignore")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Errore durante l'analisi di rete: {str(e)}")

    # 3. Motore di Analisi (Heuristics Engine)
    soup = BeautifulSoup(html, "html.parser")
    
    # Estraiamo i link social per trovare "link morti"
    all_links = soup.find_all("a", href=True)
    dead_links = 0
    social_domains = [r"twitter\.com$", r"linkedin\.com$", r"facebook\.com$", r"instagram\.com$"]
    
    for link in all_links:
        href = link["href"].strip().lower()
        if href in ["#", "", "javascript:void(0)", "javascript:void(0);"]:
            dead_links += 1
        else:
            for pattern in social_domains:
                if re.search(pattern, href):
                    dead_links += 1

    # Pulizia del testo per trovare i cliché degli LLM
    for tag in soup(["script", "style", "nav", "footer"]):
        tag.decompose()
    clean_text = soup.get_text().lower()

    ai_cliche_count = 0
    for cliche in AI_MARKETING_CLICHES:
        if re.search(cliche, clean_text):
            ai_cliche_count += 1

    # Calcolo dei punteggi di rischio
    ai_probability = min(ai_cliche_count * 20, 95)
    if ai_probability == 0: 
        ai_probability = 5

    # Calcolo del Trust Score complessivo (da 1 a 100)
    deductions = (min(dead_links * 8, 45) + min(ai_cliche_count * 15, 45))
    trust_score = max(100 - deductions, 1)

    if trust_score > 75:
        risk_level = "LOW"
    elif trust_score > 40:
        risk_level = "MEDIUM"
    else:
        risk_level = "CRITICAL"

    # 4. Salvataggio su DB per la cache futura
    try:
        supabase.table("kyc_verifications").upsert({
            "url": target_url,
            "trust_score": trust_score,
            "risk_level": risk_level,
            "ai_text_probability": ai_probability,
            "broken_links_count": dead_links
        }, on_conflict="url").execute()
    except Exception:
        pass

    return {
        "status": "success",
        "source": "live",
        "target_url": target_url,
        "corporate_trust_score": trust_score,
        "risk_level": risk_level,
        "analysis": {
            "ai_text_probability": f"{ai_probability}%",
            "dead_or_placeholder_links": dead_links
        }
    }
