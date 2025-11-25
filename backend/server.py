from fastapi import FastAPI, APIRouter, HTTPException, UploadFile, File
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Dict, Optional, Any
import uuid
from datetime import datetime, timezone
import requests
import socket
import hashlib
import re
from io import BytesIO
from PIL import Image
import exifread
import whois
import dns.resolver

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# API Keys
HUNTER_API_KEY = os.environ.get('HUNTER_API_KEY')
NUMVERIFY_API_KEY = os.environ.get('NUMVERIFY_API_KEY')
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')

# Create the main app
app = FastAPI()
api_router = APIRouter(prefix="/api")

# ============= MODELS =============

class UsernameRequest(BaseModel):
    username: str

class EmailRequest(BaseModel):
    email: str

class PhoneRequest(BaseModel):
    phone: str

class DomainRequest(BaseModel):
    domain: str

class PortScanRequest(BaseModel):
    target: str
    ports: Optional[str] = "21,22,23,25,80,443,3306,3389,8080,8443"

class ReputationRequest(BaseModel):
    target: str
    target_type: str  # "ip" or "domain"

class HashRequest(BaseModel):
    hash_value: str

# ============= USERNAME ANALYZER =============

@api_router.post("/analyze/username")
async def analyze_username(request: UsernameRequest):
    """Analyze username across popular platforms"""
    username = request.username.strip()
    
    platforms = [
        {"name": "GitHub", "url": f"https://github.com/{username}", "check_url": f"https://github.com/{username}"},
        {"name": "Twitter/X", "url": f"https://twitter.com/{username}", "check_url": f"https://twitter.com/{username}"},
        {"name": "Instagram", "url": f"https://instagram.com/{username}", "check_url": f"https://instagram.com/{username}"},
        {"name": "Reddit", "url": f"https://reddit.com/user/{username}", "check_url": f"https://reddit.com/user/{username}"},
        {"name": "YouTube", "url": f"https://youtube.com/@{username}", "check_url": f"https://youtube.com/@{username}"},
        {"name": "TikTok", "url": f"https://tiktok.com/@{username}", "check_url": f"https://tiktok.com/@{username}"},
        {"name": "LinkedIn", "url": f"https://linkedin.com/in/{username}", "check_url": f"https://linkedin.com/in/{username}"},
        {"name": "Pinterest", "url": f"https://pinterest.com/{username}", "check_url": f"https://pinterest.com/{username}"},
        {"name": "Twitch", "url": f"https://twitch.tv/{username}", "check_url": f"https://twitch.tv/{username}"},
        {"name": "Medium", "url": f"https://medium.com/@{username}", "check_url": f"https://medium.com/@{username}"},
    ]
    
    results = []
    for platform in platforms:
        try:
            response = requests.get(platform["check_url"], timeout=5, allow_redirects=True)
            exists = response.status_code == 200
            results.append({
                "platform": platform["name"],
                "url": platform["url"],
                "exists": exists,
                "status_code": response.status_code
            })
        except:
            results.append({
                "platform": platform["name"],
                "url": platform["url"],
                "exists": False,
                "status_code": 0
            })
    
    found_count = sum(1 for r in results if r["exists"])
    
    return {
        "username": username,
        "total_platforms": len(platforms),
        "found_on": found_count,
        "results": results
    }

# ============= EMAIL ANALYZER =============

@api_router.post("/analyze/email")
async def analyze_email(request: EmailRequest):
    """Analyze email using Hunter.io API"""
    email = request.email.strip()
    
    # Validate email format
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_regex, email):
        raise HTTPException(status_code=400, detail="Invalid email format")
    
    try:
        # Hunter.io Email Verifier API
        url = f"https://api.hunter.io/v2/email-verifier"
        params = {
            "email": email,
            "api_key": HUNTER_API_KEY
        }
        
        response = requests.get(url, params=params, timeout=10)
        data = response.json()
        
        if response.status_code == 200 and "data" in data:
            email_data = data["data"]
            return {
                "email": email,
                "status": email_data.get("status", "unknown"),
                "score": email_data.get("score", 0),
                "regexp": email_data.get("regexp", False),
                "gibberish": email_data.get("gibberish", False),
                "disposable": email_data.get("disposable", False),
                "webmail": email_data.get("webmail", False),
                "mx_records": email_data.get("mx_records", False),
                "smtp_server": email_data.get("smtp_server", False),
                "smtp_check": email_data.get("smtp_check", False),
                "accept_all": email_data.get("accept_all", False),
                "block": email_data.get("block", False),
                "sources": email_data.get("sources", [])
            }
        else:
            raise HTTPException(status_code=500, detail=data.get("errors", [{}])[0].get("details", "API Error"))
            
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Request failed: {str(e)}")

# ============= PHONE ANALYZER =============

@api_router.post("/analyze/phone")
async def analyze_phone(request: PhoneRequest):
    """Analyze phone number using Numverify API"""
    phone = request.phone.strip()
    
    try:
        url = f"http://apilayer.net/api/validate"
        params = {
            "access_key": NUMVERIFY_API_KEY,
            "number": phone,
            "format": 1
        }
        
        response = requests.get(url, params=params, timeout=10)
        data = response.json()
        
        if data.get("valid"):
            return {
                "phone": phone,
                "valid": data.get("valid", False),
                "number": data.get("number", ""),
                "local_format": data.get("local_format", ""),
                "international_format": data.get("international_format", ""),
                "country_prefix": data.get("country_prefix", ""),
                "country_code": data.get("country_code", ""),
                "country_name": data.get("country_name", ""),
                "location": data.get("location", ""),
                "carrier": data.get("carrier", ""),
                "line_type": data.get("line_type", "")
            }
        else:
            return {
                "phone": phone,
                "valid": False,
                "error": data.get("error", {}).get("info", "Invalid phone number")
            }
            
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Request failed: {str(e)}")

# ============= DOMAIN ANALYZER =============

@api_router.post("/analyze/domain")
async def analyze_domain(request: DomainRequest):
    """Analyze domain with WHOIS and DNS records"""
    domain = request.domain.strip()
    
    result = {
        "domain": domain,
        "whois": {},
        "dns": {}
    }
    
    # WHOIS Lookup
    try:
        w = whois.whois(domain)
        result["whois"] = {
            "domain_name": w.domain_name if isinstance(w.domain_name, str) else w.domain_name[0] if w.domain_name else domain,
            "registrar": w.registrar,
            "creation_date": str(w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date) if w.creation_date else None,
            "expiration_date": str(w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date) if w.expiration_date else None,
            "updated_date": str(w.updated_date[0] if isinstance(w.updated_date, list) else w.updated_date) if w.updated_date else None,
            "name_servers": w.name_servers if w.name_servers else [],
            "status": w.status if w.status else [],
            "emails": w.emails if w.emails else [],
            "org": w.org if hasattr(w, 'org') else None,
        }
    except Exception as e:
        result["whois"]["error"] = str(e)
    
    # DNS Records
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            result["dns"][record_type] = [str(rdata) for rdata in answers]
        except:
            result["dns"][record_type] = []
    
    return result

# ============= PORT SCANNER =============

@api_router.post("/scan/ports")
async def scan_ports(request: PortScanRequest):
    """Scan common ports on target"""
    target = request.target.strip()
    ports_str = request.ports
    
    # Parse ports
    try:
        ports = [int(p.strip()) for p in ports_str.split(',')]
    except:
        raise HTTPException(status_code=400, detail="Invalid port format")
    
    # Resolve hostname to IP
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        raise HTTPException(status_code=400, detail="Cannot resolve hostname")
    
    results = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        
        status = "open" if result == 0 else "closed"
        service = get_service_name(port)
        
        results.append({
            "port": port,
            "status": status,
            "service": service
        })
        sock.close()
    
    open_ports = [r for r in results if r["status"] == "open"]
    
    return {
        "target": target,
        "ip": ip,
        "total_scanned": len(ports),
        "open_ports": len(open_ports),
        "results": results
    }

def get_service_name(port: int) -> str:
    """Get common service name for port"""
    services = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        8080: "HTTP-Proxy",
        8443: "HTTPS-Alt"
    }
    return services.get(port, "Unknown")

# ============= REPUTATION CHECKER =============

@api_router.post("/check/reputation")
async def check_reputation(request: ReputationRequest):
    """Check IP/Domain reputation using VirusTotal"""
    target = request.target.strip()
    target_type = request.target_type
    
    try:
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY
        }
        
        if target_type == "ip":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
        else:
            url = f"https://www.virustotal.com/api/v3/domains/{target}"
        
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            last_analysis = attributes.get("last_analysis_stats", {})
            
            return {
                "target": target,
                "type": target_type,
                "reputation": attributes.get("reputation", 0),
                "malicious": last_analysis.get("malicious", 0),
                "suspicious": last_analysis.get("suspicious", 0),
                "harmless": last_analysis.get("harmless", 0),
                "undetected": last_analysis.get("undetected", 0),
                "total_votes": {
                    "harmless": attributes.get("total_votes", {}).get("harmless", 0),
                    "malicious": attributes.get("total_votes", {}).get("malicious", 0)
                },
                "categories": attributes.get("categories", {}),
                "last_analysis_date": attributes.get("last_analysis_date", 0)
            }
        else:
            raise HTTPException(status_code=response.status_code, detail="VirusTotal API error")
            
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Request failed: {str(e)}")

# ============= METADATA EXTRACTOR =============

@api_router.post("/extract/metadata")
async def extract_metadata(file: UploadFile = File(...)):
    """Extract EXIF metadata from image"""
    try:
        contents = await file.read()
        image_file = BytesIO(contents)
        
        # Try with PIL first
        try:
            img = Image.open(image_file)
            basic_info = {
                "filename": file.filename,
                "format": img.format,
                "mode": img.mode,
                "size": img.size,
                "width": img.width,
                "height": img.height,
            }
            
            # Get EXIF data
            exif_data = {}
            if hasattr(img, '_getexif') and img._getexif():
                exif = img._getexif()
                for tag_id, value in exif.items():
                    tag = Image.TAGS.get(tag_id, tag_id)
                    exif_data[tag] = str(value)
            
            basic_info["exif"] = exif_data
        except Exception as e:
            basic_info = {"error": str(e)}
        
        # Try with exifread
        image_file.seek(0)
        tags = exifread.process_file(image_file)
        
        exifread_data = {}
        for tag in tags.keys():
            if tag not in ('JPEGThumbnail', 'TIFFThumbnail', 'Filename', 'EXIF MakerNote'):
                exifread_data[tag] = str(tags[tag])
        
        return {
            "basic_info": basic_info,
            "detailed_exif": exifread_data
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to process image: {str(e)}")

# ============= HASH ANALYZER =============

@api_router.post("/analyze/hash")
async def analyze_hash(request: HashRequest):
    """Identify hash type"""
    hash_value = request.hash_value.strip()
    hash_length = len(hash_value)
    
    # Determine hash type based on length and pattern
    hash_types = []
    
    if hash_length == 32 and re.match(r'^[a-fA-F0-9]{32}$', hash_value):
        hash_types.append("MD5")
    
    if hash_length == 40 and re.match(r'^[a-fA-F0-9]{40}$', hash_value):
        hash_types.append("SHA-1")
    
    if hash_length == 64 and re.match(r'^[a-fA-F0-9]{64}$', hash_value):
        hash_types.append("SHA-256")
    
    if hash_length == 128 and re.match(r'^[a-fA-F0-9]{128}$', hash_value):
        hash_types.append("SHA-512")
    
    if hash_length == 56 and re.match(r'^[a-fA-F0-9]{56}$', hash_value):
        hash_types.append("SHA-224")
    
    if hash_length == 96 and re.match(r'^[a-fA-F0-9]{96}$', hash_value):
        hash_types.append("SHA-384")
    
    # bcrypt, NTLM, etc.
    if hash_value.startswith('$2a$') or hash_value.startswith('$2b$') or hash_value.startswith('$2y$'):
        hash_types.append("bcrypt")
    
    if hash_length == 32 and ':' in hash_value:
        hash_types.append("NTLM")
    
    return {
        "hash": hash_value,
        "length": hash_length,
        "possible_types": hash_types if hash_types else ["Unknown"],
        "cracking_resources": [
            {"name": "CrackStation", "url": "https://crackstation.net/"},
            {"name": "HashKiller", "url": "https://hashkiller.io/"},
            {"name": "OnlineHashCrack", "url": "https://www.onlinehashcrack.com/"},
        ]
    }

# ============= BASIC ROUTES =============

@api_router.get("/")
async def root():
    return {"message": "OSINT UI API - All systems operational"}

# Include router
app.include_router(api_router)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
