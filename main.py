from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, IPvAnyAddress
from typing import Dict, List, Optional, Tuple, Any
import requests
import socket
import asyncio
import aiohttp
from datetime import datetime
import ipaddress
import concurrent.futures
import json
import logging
from functools import lru_cache
import maxminddb
import re
import ssl
import time
from pydantic import ConfigDict

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Enhanced VPN Detection API",
    description="API для продвинутого определения VPN с использованием множества методов",
    version="2.0.0"
)

# Добавляем CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class IPCheckResult(BaseModel):
    ip: str
    is_vpn: bool
    confidence_score: float
    risk_level: str
    details: Dict[str, Any]
    checked_at: datetime
    response_time: float
    
    model_config = ConfigDict(arbitrary_types_allowed=True)

class VPNDetector:
    def __init__(self):
        self.vpn_asn_list = self._load_vpn_asn_list()
        self.known_vpn_providers = self._load_vpn_providers()
        
    @staticmethod
    @lru_cache(maxsize=1000)
    def _load_vpn_asn_list() -> List[str]:
        # В реальном приложении здесь бы загружался список ASN известных VPN-провайдеров
        return ["AS9009", "AS12876", "AS16276", "AS20860"]
        
    @staticmethod
    @lru_cache(maxsize=1000)
    def _load_vpn_providers() -> List[str]:
        return ["nordvpn", "expressvpn", "protonvpn", "mullvad", "privateinternetaccess"]

    async def check_reverse_dns(self, ip: str) -> Tuple[bool, str]:
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            vpn_indicators = ["vpn", "proxy", "tor", "exit", "node", "relay"]
            return any(indicator in hostname.lower() for indicator in vpn_indicators), hostname
        except:
            return False, ""

    async def check_ssl_certificates(self, ip: str) -> bool:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((ip, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert()
                    org = dict(x[0] for x in cert['subject']).get('organizationName', '')
                    return any(provider in org.lower() for provider in self.known_vpn_providers)
        except:
            return False

    async def check_geolocation_mismatch(self, ip: str) -> Tuple[bool, Dict[str, Any]]:
        try:
            async with aiohttp.ClientSession() as session:
                apis = [
                    f"http://ip-api.com/json/{ip}",
                    f"https://ipapi.co/{ip}/json/"
                ]
                locations = []
                for api in apis:
                    async with session.get(api) as response:
                        if response.status == 200:
                            data = await response.json()
                            locations.append(data.get('country'))
                
                return len(set(locations)) > 1, {"locations": locations}
        except:
            return False, {}

    def check_common_vpn_ports(self, ip: str) -> Dict[int, bool]:
        common_vpn_ports = {
            1194: "OpenVPN",
            500: "IPSec",
            4500: "IPSec NAT-T",
            1701: "L2TP",
            1723: "PPTP",
            8080: "OpenVPN",
            443: "OpenVPN/SSL",
            992: "SSL VPN",
            1293: "IPSec",
            51820: "WireGuard"
        }
        
        results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_port = {
                executor.submit(self._check_port, ip, port): (port, protocol)
                for port, protocol in common_vpn_ports.items()
            }
            for future in concurrent.futures.as_completed(future_to_port):
                port, protocol = future_to_port[future]
                try:
                    is_open = future.result()
                    results[port] = is_open
                except Exception as e:
                    logger.error(f"Error checking port {port}: {str(e)}")
                    results[port] = False
        
        return results

    def _check_port(self, ip: str, port: int) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False

    async def check_blacklists(self, ip: str) -> Dict[str, bool]:
        blacklists = {
            "abuseipdb": f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}",
            "torproject": f"https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip={ip}",
        }
        
        results = {}
        async with aiohttp.ClientSession() as session:
            for name, url in blacklists.items():
                try:
                    async with session.get(url) as response:
                        results[name] = response.status == 200
                except:
                    results[name] = False
        
        return results

vpn_detector = VPNDetector()

@app.get("/check/{ip}", response_model=IPCheckResult)
async def check_ip(ip: str, user_agent: str = Header(None)):
    start_time = time.time()
    try:
        # Валидация IP
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid IP address")

        # Параллельные проверки
        tasks = [
            vpn_detector.check_reverse_dns(ip),
            vpn_detector.check_geolocation_mismatch(ip),
            vpn_detector.check_blacklists(ip),
        ]
        
        dns_result, geo_result, blacklist_result = await asyncio.gather(*tasks)
        
        # Проверка портов в отдельном потоке
        ports_result = vpn_detector.check_common_vpn_ports(ip)
        
        # Подсчет индикаторов VPN
        vpn_indicators = 0
        total_checks = 0
        
        # DNS проверка
        if dns_result[0]:
            vpn_indicators += 2
        total_checks += 2
        
        # Геолокация
        if geo_result[0]:
            vpn_indicators += 3
        total_checks += 3
        
        # Порты
        open_ports = sum(1 for is_open in ports_result.values() if is_open)
        if open_ports > 0:
            vpn_indicators += min(open_ports * 2, 6)
        total_checks += 6
        
        # Черные списки
        blacklist_matches = sum(1 for is_listed in blacklist_result.values() if is_listed)
        if blacklist_matches > 0:
            vpn_indicators += blacklist_matches * 2
        total_checks += 4
        
        # Расчет итогового результата
        confidence_score = vpn_indicators / total_checks if total_checks > 0 else 0.0
        
        # Определение уровня риска
        risk_level = "Low"
        if confidence_score > 0.7:
            risk_level = "High"
        elif confidence_score > 0.4:
            risk_level = "Medium"
            
        details = {
            "reverse_dns": {
                "is_vpn": dns_result[0],
                "hostname": dns_result[1]
            },
            "geolocation": {
                "mismatch_detected": geo_result[0],
                "details": geo_result[1]
            },
            "open_vpn_ports": ports_result,
            "blacklists": blacklist_result,
            "analysis_methods": [
                "reverse_dns",
                "geolocation",
                "port_scanning",
                "blacklist_checking"
            ]
        }
        
        return IPCheckResult(
            ip=ip,
            is_vpn=confidence_score > 0.5,
            confidence_score=confidence_score,
            risk_level=risk_level,
            details=details,
            checked_at=datetime.now(),
            response_time=time.time() - start_time
        )
        
    except Exception as e:
        logger.error(f"Error checking IP {ip}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now()}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 
    
