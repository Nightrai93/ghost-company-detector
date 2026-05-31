import os
import re
import ipaddress
import asyncio
import socket
import httpx
from datetime import datetime, timedelta
from urllib.parse import urlparse
from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel
from bs4 import BeautifulSoup
from supabase import create_client, Client

app = FastAPI(title="Anti-Synthetic Corporate KYC API")

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
RAPIDAPI_SECRET = os.getenv("RAPIDAPI_PROXY_SECRET")

CACHE_TTL_HOURS = 24

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

AI_MARKETING_CLICHES = [
    r"in today's fast-paced", r"digital landscape", r"cutting-edge solutions",
    r"revolutionize the way", r"delivering unparalleled", r"at our core",
    r"testament to our commitment", r"foster a collaborative", r"beacon of innovation",
    r"elevate your business", r"seamless integration"
]

class KYCRequest(BaseModel):
    url: str

class PinnedIPTransport(httpx.AsyncHTTPTransport):
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        hostname = request.url.host
        port = request.url.port or (443 if request.url.scheme == "https" else 80)

        loop = asyncio.get_running_loop()
        try:
            addr_info = await loop.getaddrinfo(
                hostname, port, proto=socket.IPPROTO_TCP
            )
            target_ip = addr_info[0][4][0]
        except Exception as e:
            raise httpx.ConnectError(f"DNS resolution failed for the given URL: {e}")

        ip_obj = ipaddress.ip_address(target_ip)
        if (ip_obj.is_private or ip_obj.is_loopback or
                ip_obj.is_link_local or ip_obj.is_reserved or ip_obj.is_multicast):
            raise httpx.ConnectError("Access denied: SSRF vulnerability blocked.")

        new_url = request.url.copy_with(host=target_ip)
        headers = {k: v for k, v in request.headers.items() if k.lower() != "host"}
        headers["host"] = hostname
        extensions = {**request.extensions, "sni_hostname": hostname.encode("ascii")}

        new_request = httpx.Request(
            method=request.method,
            url=new_url,
            headers=headers,
            extensions=extensions,
        )

        return await super().handle_async_request(new_request)

async def verify_rapidapi_gate(x_rapidapi_proxy_secret: str = Header(None)):
    if not RAPIDAPI_SECRET:
        return
    if x_rapidapi_proxy_secret != RAPIDAPI_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized request. Please go through the RapidAPI gateway.")

async def _db_get_cached(url: str):
    cutoff = (datetime.utcnow() - timedelta(hours=CACHE_TTL_HOURS)).isoformat()
    return await asyncio.to_thread(
        lambda: supabase.table("kyc_verifications")
            .select("*")
            .eq("url", url)
            .gte("checked_at", cutoff)  # CORRETTO IN checked_at
            .execute()
    )

async def _db_upsert(data: dict):
    return await asyncio.to_thread(
        lambda: supabase.table("kyc_verifications").upsert(data, on_conflict="url").execute()
    )

@app.get("/")
def health():
    return {"status": "healthy", "engine": "TrustShield KYC V1"}

@app.post("/verify")
async def verify_company(payload: KYCRequest, _ = Depends(verify_rapidapi_gate)):
    target_url = str(payload.url).strip()

    parsed_url = urlparse(target_url)
    if parsed_url.scheme not in ("http", "https"):
        raise HTTPException(status_code=400, detail="Only HTTP and HTTPS URLs are supported.")
    if not parsed_url.netloc:
        raise HTTPException(status_code=400, detail="Invalid URL: no host found.")

    # 1. Atomic cache check (TTL-aware)
    try:
        cached = await _db_get_cached(target_url)
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

    # 2. Secure streaming scrape
    html = None
    http_status = 200
    error_mode = None

    try:
        transport = PinnedIPTransport(verify=True)
        async with httpx.AsyncClient(transport=transport, timeout=8.0, follow_redirects=True) as client:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5"
            }
            async with client.stream("GET", target_url, headers=headers) as response:
                http_status = response.status_code
                if response.status_code != 200:
                    error_mode = f"HTTP_UNAVAILABLE_{response.status_code}"
                else:
                    chunks = []
                    size = 0
                    async for chunk in response.aiter_bytes(chunk_size=8192):
                        chunks.append(chunk)
                        size += len(chunk)
                        if size > 3 * 1024 * 1024:
                            error_mode = "PAGE_TOO_LARGE"
                            break
                    if not error_mode:
                        html = b"".join(chunks).decode("utf-8", errors="ignore")
    except Exception as e:
        http_status = 0
        error_mode = f"CONNECTION_FAILED_{type(e).__name__}"

    # 3. Graceful failure handling (Non va più in cache)
    if error_mode or http_status != 200:
        trust_score = 15
        risk_level = "CRITICAL"

        return {
            "status": "success",
            "source": "live_audit_anomaly",
            "target_url": target_url,
            "corporate_trust_score": trust_score,
            "risk_level": risk_level,
            "analysis": {
                "verification_failed": True,
                "failure_reason": f"Target corporate site is unreachable or blocking connection. Status: {http_status} ({error_mode})."
            }
        }

    # 4. Heuristics Engine
    soup = BeautifulSoup(html, "html.parser")

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
                    parsed = urlparse(href)
                    if not parsed.path.strip("/"):
                        dead_links += 1

    for tag in soup(["script", "style", "nav", "footer"]):
        tag.decompose()
    clean_text = soup.get_text().lower()

    ai_cliche_count = sum(
        1 for cliche in AI_MARKETING_CLICHES if re.search(cliche, clean_text)
    )

    ai_probability = min(ai_cliche_count * 20, 95) or 5
    deductions = min(dead_links * 8, 45) + min(ai_cliche_count * 15, 45)
    trust_score = max(100 - deductions, 1)

    if trust_score > 75:
        risk_level = "LOW"
    elif trust_score > 40:
        risk_level = "MEDIUM"
    else:
        risk_level = "CRITICAL"

    # 5. Persist successful analysis to cache
    try:
        await _db_upsert({
            "url": target_url,
            "trust_score": trust_score,
            "risk_level": risk_level,
            "ai_text_probability": ai_probability,
            "broken_links_count": dead_links,
            "checked_at": datetime.utcnow().isoformat()  # CORRETTO IN checked_at
        })
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
