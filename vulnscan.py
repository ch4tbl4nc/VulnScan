import os
import json
from typing import Optional, Dict, Any, List, Set, Tuple
from dataclasses import dataclass
from datetime import datetime
import base64
from cryptography.fernet import Fernet
import yaml
import logging
import asyncio
import aiohttp
import time
import sys
import nmap
from concurrent.futures import ThreadPoolExecutor
from prettytable import PrettyTable
from colorama import Fore, Style, init
from pathlib import Path

init(autoreset=True)

DEFAULT_START_PORT = 1
DEFAULT_END_PORT = 65535
CHUNK_SIZE = 1000
MAX_CONCURRENT_SCANS = 1000
SCAN_TIMEOUT = 2.0
VULNERABILITY_CACHE: Dict[str, List[str]] = {}

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

@dataclass
class APIConfig:
    vulners_api_key: Optional[str] = None
    shodan_api_key: Optional[str] = None
    censys_api_key: Optional[str] = None
    config_path: str = "config/api_config.yaml"
    encryption_key_path: str = "config/.encryption_key"

class APIConfigManager:
    def __init__(self):
        self.config = APIConfig()
        self._setup_config_directory()
        self._load_or_create_encryption_key()
        self._load_config()

    def _setup_config_directory(self) -> None:
        config_dir = os.path.dirname(self.config.config_path)
        os.makedirs(config_dir, exist_ok=True)

    def _load_or_create_encryption_key(self) -> None:
        try:
            if os.path.exists(self.config.encryption_key_path):
                with open(self.config.encryption_key_path, 'rb') as key_file:
                    self.encryption_key = key_file.read()
            else:
                self.encryption_key = Fernet.generate_key()
                with open(self.config.encryption_key_path, 'wb') as key_file:
                    key_file.write(self.encryption_key)
            self.cipher_suite = Fernet(self.encryption_key)
        except Exception as e:
            logging.error(f"Error during encryption key management: {e}")
            raise

    def _encrypt_value(self, value: str) -> str:
        if not value:
            return ""
        return base64.b64encode(
            self.cipher_suite.encrypt(value.encode())
        ).decode()

    def _decrypt_value(self, encrypted_value: str) -> str:
        if not encrypted_value:
            return ""
        try:
            return self.cipher_suite.decrypt(
                base64.b64decode(encrypted_value.encode())
            ).decode()
        except Exception:
            return ""

    def _load_config(self) -> None:
        try:
            if os.path.exists(self.config.config_path):
                with open(self.config.config_path, 'r') as config_file:
                    config_data = yaml.safe_load(config_file)
                    if config_data:
                        self.config.vulners_api_key = self._decrypt_value(
                            config_data.get('vulners_api_key', ''))
                        self.config.shodan_api_key = self._decrypt_value(
                            config_data.get('shodan_api_key', ''))
                        self.config.censys_api_key = self._decrypt_value(
                            config_data.get('censys_api_key', ''))
        except Exception as e:
            logging.error(f"Error loading configuration: {e}")

    def save_config(self) -> None:
        try:
            config_data = {
                'vulners_api_key': self._encrypt_value(self.config.vulners_api_key or ''),
                'shodan_api_key': self._encrypt_value(self.config.shodan_api_key or ''),
                'censys_api_key': self._encrypt_value(self.config.censys_api_key or ''),
                'last_updated': datetime.now().isoformat()
            }
            
            with open(self.config.config_path, 'w') as config_file:
                yaml.dump(config_data, config_file)
            
            logging.info("Configuration successfully saved")
        except Exception as e:
            logging.error(f"Error saving configuration: {e}")
            raise

    def get_api_key(self, service: str) -> Optional[str]:
        if hasattr(self.config, f"{service}_api_key"):
            return getattr(self.config, f"{service}_api_key")
        return None

    def update_api_key(self, service: str, api_key: str) -> None:
        if hasattr(self.config, f"{service}_api_key"):
            setattr(self.config, f"{service}_api_key", api_key)
            self.save_config()
        else:
            raise ValueError(f"Unknown API service: {service}")

    def verify_api_keys(self) -> Dict[str, bool]:
        return {
            'vulners': bool(self.config.vulners_api_key),
            'shodan': bool(self.config.shodan_api_key),
            'censys': bool(self.config.censys_api_key)
        }

class ServiceDetector:
    def __init__(self):
        self.nmap_scanner = nmap.PortScanner()
        self.service_cache: Dict[Tuple[str, int], Dict] = {}
        self.common_service_ports = {
            'http': [80, 8080, 8000, 8888],
            'https': [443, 8443],
            'ftp': [21],
            'ssh': [22],
            'telnet': [23],
            'smtp': [25],
            'dns': [53],
            'pop3': [110],
            'imap': [143],
            'ldap': [389],
            'mysql': [3306],
            'rdp': [3389],
            'postgresql': [5432],
            'vnc': [5900],
            'redis': [6379],
            'mongodb': [27017]
        }
        
    async def detect_service(self, ip: str, port: int) -> Dict:
        cache_key = (ip, port)
        if cache_key in self.service_cache:
            return self.service_cache[cache_key]

        service_info = {
            'name': 'unknown',
            'product': '',
            'version': '',
            'extrainfo': '',
            'cpe': '',
            'scripts': {},
            'protocol': '',
            'state': '',
            'banner': ''
        }

        try:
            self.nmap_scanner.scan(
                ip, 
                str(port), 
                arguments='-sV -sC -Pn --version-intensity 9 --min-rate 1000'
            )
            
            if ip in self.nmap_scanner.all_hosts():
                tcp_info = self.nmap_scanner[ip].get('tcp', {}).get(port, {})
                
                if tcp_info:
                    service_info.update({
                        'name': tcp_info.get('name', 'unknown'),
                        'product': tcp_info.get('product', ''),
                        'version': tcp_info.get('version', ''),
                        'extrainfo': tcp_info.get('extrainfo', ''),
                        'cpe': tcp_info.get('cpe', ''),
                        'scripts': tcp_info.get('script', {}),
                        'protocol': 'tcp',
                        'state': tcp_info.get('state', ''),
                    })
                    
                    try:
                        banner = await self._get_banner(ip, port)
                        if banner:
                            service_info['banner'] = banner
                    except Exception:
                        pass
                    
                if port in self.common_service_ports['http'] + self.common_service_ports['https']:
                    await self._enhance_web_service_info(ip, port, service_info)

        except Exception as e:
            logging.error(f"Error during service detection on port {port}: {e}")

        self.service_cache[cache_key] = service_info
        return service_info

    async def _get_banner(self, ip: str, port: int) -> str:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=3.0
            )
            
            writer.write(b"\r\n")
            await writer.drain()
            
            banner = await asyncio.wait_for(reader.read(1024), timeout=3.0)
            writer.close()
            await writer.wait_closed()
            
            return banner.decode('utf-8', errors='ignore').strip()
        except Exception:
            return ""

    async def _enhance_web_service_info(self, ip: str, port: int, service_info: Dict) -> None:
        try:
            protocol = "https" if port in self.common_service_ports['https'] else "http"
            url = f"{protocol}://{ip}:{port}"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=5, verify_ssl=False) as response:
                    headers = dict(response.headers)
                    service_info['web_info'] = {
                        'status': response.status,
                        'server': headers.get('Server', ''),
                        'powered_by': headers.get('X-Powered-By', ''),
                        'content_type': headers.get('Content-Type', ''),
                        'headers': headers
                    }
        except Exception:
            pass

class VulnerabilityScanner:
    def __init__(self, api_config: APIConfigManager):
        self.api_config = api_config
        self.vulnerability_cache: Dict[str, List[Dict]] = {}
        self.cve_details_base_url = "https://nvd.nist.gov/vuln/detail/"
        
    async def search_vulnerabilities(self, session: aiohttp.ClientSession, service_info: Dict) -> List[Dict]:
        vulns = []
        
        service_fingerprint = (
            f"{service_info['name']}:{service_info['product']}:{service_info['version']}"
        )
        
        if service_fingerprint in self.vulnerability_cache:
            return self.vulnerability_cache[service_fingerprint]

        tasks = []
        
        vulners_key = self.api_config.get_api_key('vulners')
        if vulners_key:
            tasks.append(self._search_vulners(session, service_info, vulners_key))

        tasks.append(self._search_nvd(session, service_info))
        
        shodan_key = self.api_config.get_api_key('shodan')
        if shodan_key:
            tasks.append(self._search_shodan(session, service_info, shodan_key))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, list):
                vulns.extend(result)

        unique_vulns = self._deduplicate_vulnerabilities(vulns)
        
        enriched_vulns = await self._enrich_vulnerabilities(session, unique_vulns)
        
        self.vulnerability_cache[service_fingerprint] = enriched_vulns
        return enriched_vulns

    async def _enrich_vulnerabilities(self, session: aiohttp.ClientSession, vulns: List[Dict]) -> List[Dict]:
        for vuln in vulns:
            if vuln.get('id', '').startswith('CVE-'):
                vuln['nvd_url'] = f"{self.cve_details_base_url}{vuln['id']}"
            
            cvss_score = float(vuln.get('cvss', 0) or 0)
            vuln['risk_level'] = self._calculate_risk_level(cvss_score)

            vuln['remediation'] = self._generate_remediation_advice(vuln)

        return vulns

    def _calculate_risk_level(self, cvss_score: float) -> str:
        if cvss_score >= 9.0:
            return "CRITICAL"
        elif cvss_score >= 7.0:
            return "HIGH"
        elif cvss_score >= 4.0:
            return "MEDIUM"
        elif cvss_score > 0:
            return "LOW"
        return "INFO"

    def _generate_remediation_advice(self, vuln: Dict) -> str:
        title = vuln.get('title', '').lower()
        if 'buffer overflow' in title:
            return "Update to the latest version and enable security features like ASLR and DEP"
        elif 'sql injection' in title:
            return "Implement proper input validation and parameterized queries"
        elif 'cross-site scripting' in title or 'xss' in title:
            return "Implement input validation and output encoding"
        elif 'configuration' in title:
            return "Review and update security configuration settings"
        return "Update to the latest version and apply security patches"
        
    async def _search_vulners(self, session: aiohttp.ClientSession, service_info: Dict, api_key: str) -> List[Dict]:
        vulns = []
        try:
            query = f"product:{service_info['product']} version:{service_info['version']}"
            async with session.get(
                "https://vulners.com/api/v3/search/lucene/",
                params={"query": query},
                headers={"API-Key": api_key}
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    if 'data' in data and 'documents' in data['data']:
                        for doc in data['data']['documents']:
                            vulns.append({
                                'source': 'vulners',
                                'id': doc.get('id', ''),
                                'title': doc.get('title', ''),
                                'description': doc.get('description', ''),
                                'cvss': doc.get('cvss', {}).get('score', 0),
                                'published': doc.get('published', ''),
                                'references': doc.get('references', [])
                            })
        except Exception as e:
            logging.error(f"Vulners search error: {e}")
        return vulns

    async def _search_nvd(self, session: aiohttp.ClientSession, service_info: Dict) -> List[Dict]:
        vulns = []
        try:
            if service_info['cpe']:
                async with session.get(
                    f"https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params={"cpeName": service_info['cpe']}
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        for vuln in data.get('vulnerabilities', []):
                            cve = vuln.get('cve', {})
                            vulns.append({
                                'source': 'nvd',
                                'id': cve.get('id', ''),
                                'title': cve.get('descriptions', [{}])[0].get('value', ''),
                                'description': cve.get('descriptions', [{}])[0].get('value', ''),
                                'cvss': cve.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore', 0),
                                'published': cve.get('published', ''),
                                'references': [ref.get('url', '') for ref in cve.get('references', [])]
                            })
        except Exception as e:
            logging.error(f"NVD search error: {e}")
        return vulns

    async def _search_shodan(self, session: aiohttp.ClientSession, service_info: Dict, api_key: str) -> List[Dict]:
        vulns = []
        try:
            query = f"product:{service_info['product']} version:{service_info['version']}"
            async with session.get(
                f"https://api.shodan.io/shodan/host/search",
                params={"key": api_key, "query": query}
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    for match in data.get('matches', []):
                        for vuln in match.get('vulns', []):
                            vulns.append({
                                'source': 'shodan',
                                'id': vuln,
                                'title': match['vulns'][vuln].get('summary', ''),
                                'description': match['vulns'][vuln].get('description', ''),
                                'cvss': match['vulns'][vuln].get('cvss', 0),
                                'published': match['vulns'][vuln].get('published', ''),
                                'references': match['vulns'][vuln].get('references', [])
                            })
        except Exception as e:
            logging.error(f"Erreur lors de la recherche Shodan: {e}")
        return vulns

    def _deduplicate_vulnerabilities(self, vulns: List[Dict]) -> List[Dict]:
        seen = set()
        unique_vulns = []
        
        for vuln in vulns:
            vuln_id = vuln['id']
            if vuln_id not in seen:
                seen.add(vuln_id)
                unique_vulns.append(vuln)
        
        return sorted(unique_vulns, key=lambda x: float(x['cvss'] or 0), reverse=True)

class ProgressBar:
    def __init__(self, total: int, prefix: str = '', suffix: str = '', 
                 decimals: int = 1, length: int = 50, 
                 fill: str = '█', unfill: str = '░') -> None:
        self.total = max(1, total)
        self.prefix = prefix
        self.suffix = suffix
        self.decimals = decimals
        self.length = length
        self.fill = fill
        self.unfill = unfill
        self.iteration = 0

    def print_progress(self) -> None:
        try:
            percent = min(100, (self.iteration / self.total) * 100)
            filled_length = int(self.length * self.iteration // self.total)
            filled_length = min(self.length, filled_length)
            bar = self.fill * filled_length + self.unfill * (self.length - filled_length)
            
            sys.stdout.write(f'\r{self.prefix} |{Fore.CYAN}{bar}{Style.RESET_ALL}| {percent:.{self.decimals}f}% {self.suffix}')
            sys.stdout.flush()
        except Exception as e:
            print_status(f"Error displaying progress: {e}", "error")

    def increment(self) -> None:
        self.iteration = min(self.total, self.iteration + 1)
        self.print_progress()

    def finish(self) -> None:
        sys.stdout.write('\n')
        sys.stdout.flush()

class LoadingSpinner:
    def __init__(self, message: str = "Loading") -> None:
        self.message = message
        self.spinners = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        self.speed = 0.1
        self._running = False

    async def start(self) -> None:
        self._running = True
        try:
            i = 0
            while self._running:
                i = (i + 1) % len(self.spinners)
                sys.stdout.write(f'\r{Fore.CYAN}{self.spinners[i]}{Style.RESET_ALL} {self.message}')
                sys.stdout.flush()
                await asyncio.sleep(self.speed)
        except Exception as e:
            print_status(f"Spinner error: {e}", "error")

    def stop(self) -> None:
        self._running = False
        try:
            sys.stdout.write('\r' + ' ' * (len(self.message) + 2) + '\r')
            sys.stdout.flush()
        except Exception:
            pass

class ConfigurationInterface:
    def __init__(self):
        self.api_config = APIConfigManager()

    def display_menu(self) -> None:
        while True:
            print(f"\n{'-'*50}")
            print("Configuring security APIs")
            print(f"{'-'*50}")
            print("1. Configuring the Vulners API key")
            print("2. Configuring the Shodan API key")
            print("3. Configuring the Censys API key")
            print("4. Check API status")
            print("5. Save and exit")
            
            choice = input("\nChoose an option (1-5): ")
            
            if choice == '1':
                key = input("Enter your Vulners API key (or leave blank to ignore): ")
                self.api_config.update_api_key('vulners', key)
            elif choice == '2':
                key = input("Enter your Shodan API key (or leave blank to ignore): ")
                self.api_config.update_api_key('shodan', key)
            elif choice == '3':
                key = input("Enter your Censys API key (or leave blank to ignore): ")
                self.api_config.update_api_key('censys', key)
            elif choice == '4':
                self._display_api_status()
            elif choice == '5':
                print("Configuration saved. Bye-bye!")
                break
            else:
                print("Invalid option. Please try again.")

    def _display_api_status(self) -> None:
        status = self.api_config.verify_api_keys()
        print("\nAPI status:")
        for api, is_configured in status.items():
            status_text = "Configured" if is_configured else "Not configured"
            status_color = Fore.GREEN if is_configured else Fore.RED
            print(f"{api.capitalize()}: {status_color}{status_text}{Style.RESET_ALL}")

def print_status(message: str, status: str = "info") -> None:
    try:
        timestamp = datetime.now().strftime("%H:%M:%S")
        colors = {
            "info": Fore.CYAN,
            "success": Fore.GREEN,
            "warning": Fore.YELLOW,
            "error": Fore.RED
        }
        status_symbols = {
            "info": "ℹ",
            "success": "✓",
            "warning": "⚠",
            "error": "✗"
        }
        color = colors.get(status, Fore.WHITE)
        symbol = status_symbols.get(status, "•")
        print(f"{Fore.BLUE}[{timestamp}]{Style.RESET_ALL} {color}{symbol} {message}{Style.RESET_ALL}")
    except Exception as e:
        print(f"Error displaying status: {e}")

async def scan_port(ip: str, port: int) -> Optional[int]:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=SCAN_TIMEOUT
        )
        writer.close()
        await writer.wait_closed()
        return port
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None
    except Exception as e:
        print_status(f"Error scanning port {port}: {e}", "error")
        return None

async def scan_ports_chunk(ip: str, start_port: int, end_port: int, progress_bar: ProgressBar) -> Set[int]:
    open_ports = set()
    try:
        tasks = [scan_port(ip, port) for port in range(start_port, end_port + 1)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for port, result in zip(range(start_port, end_port + 1), results):
            if isinstance(result, int):
                open_ports.add(port)
                print_status(f"Port {port} is open", "success")
            progress_bar.increment()
            
    except Exception as e:
        print_status(f"Error scanning chunk {start_port}-{end_port}: {e}", "error")
    
    return open_ports

async def scan_all_ports(ip: str, start_port: int, end_port: int) -> Set[int]:
    open_ports = set()
    total_ports = end_port - start_port + 1
    chunks = [(i, min(i + CHUNK_SIZE - 1, end_port)) 
              for i in range(start_port, end_port + 1, CHUNK_SIZE)]
    
    spinner = LoadingSpinner("Initializing scan...")
    spinner_task = asyncio.create_task(spinner.start())
    await asyncio.sleep(1)
    spinner.stop()
    await spinner_task
    
    print_status("Starting port scan", "info")
    progress_bar = ProgressBar(total_ports, prefix=f'{Fore.CYAN}Scanning Ports:{Style.RESET_ALL}', suffix='Complete | ', length=40)
    
    try:
        for chunk_start, chunk_end in chunks:
            chunk_open_ports = await scan_ports_chunk(ip, chunk_start, chunk_end, progress_bar)
            open_ports.update(chunk_open_ports)
    except Exception as e:
        print_status(f"Error during port scan: {e}", "error")
    finally:
        progress_bar.finish()
    
    return open_ports

async def analyze_vulnerabilities(
    session: aiohttp.ClientSession,
    open_ports: Set[int],
    progress_bar: ProgressBar,
    api_config: APIConfigManager,
    target_ip: str
) -> List[Dict]:
    results = []
    service_detector = ServiceDetector()
    vuln_scanner = VulnerabilityScanner(api_config)
    
    try:
        for port in sorted(open_ports):
            service_info = await service_detector.detect_service(target_ip, port)
            vulnerabilities = await vuln_scanner.search_vulnerabilities(session, service_info)
            
            results.append({
                'port': port,
                'service': service_info,
                'vulnerabilities': vulnerabilities
            })
            progress_bar.increment()
            
            if vulnerabilities:
                critical_vulns = [v for v in vulnerabilities if float(v['cvss'] or 0) >= 7.0]
                if critical_vulns:
                    print_status(
                        f"Port {port} ({service_info['name']}) has {len(critical_vulns)} critical vulnerabilities!",
                        "warning"
                    )
    
    except Exception as e:
        print_status(f"Error during vulnerability analysis: {e}", "error")
    
    return results

def print_banner() -> None:
    color_box = Fore.CYAN
    color_text = Fore.LIGHTBLUE_EX
    banner = f"""
 ╔════════════════════════════════════════════════════════════════════════╗
 ║ {color_text}██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗{Fore.RESET}{color_box} ║
 ║ {color_text}██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔════╝██╔══██╗████╗  ██║{Fore.RESET}{color_box} ║
 ║ {color_text}██║   ██║██║   ██║██║     ██╔██╗ ██║███████╗██║     ███████║██╔██╗ ██║{Fore.RESET}{color_box} ║
 ║ {color_text}╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║╚════██║██║     ██╔══██║██║╚██╗██║{Fore.RESET}{color_box} ║
 ║  {color_text}╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████║╚██████╗██║  ██║██║ ╚████║{Fore.RESET}{color_box} ║
 ║   {color_text}╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝{Fore.RESET}{color_box} ║
 ╚════════════════════════════════════════════════════════════════════════╝
 ╔═══════════════════════╗
 ║ {color_text}Github : ch4tbl4nc{Fore.RESET}{color_box}  ║
 ║ {color_text}Discord : ch4tbl4nc{Fore.RESET}{color_box} ║
 ╚═══════════════════════╝
    """
    print(f"{color_box}{banner}{Style.RESET_ALL}")

async def main() -> None:
    print_banner()
    
    try:
        api_config = APIConfigManager()
        
        if not any(api_config.verify_api_keys().values()):
            print_status("Aucune API configurée. Lancement de l'interface de configuration...", "warning")
            config_interface = ConfigurationInterface()
            config_interface.display_menu()
        
        print(f"\n{Fore.CYAN}┌──{Style.RESET_ALL} Scan Configuration {Fore.CYAN}───────────────────────{Style.RESET_ALL}")
        target_ip = input(f"{Fore.CYAN}├─▶{Style.RESET_ALL} Enter target IP address : ").strip()
        if not target_ip:
            raise ValueError("IP address cannot be empty")

        start_port_input = input(f"{Fore.CYAN}├─▶{Style.RESET_ALL} Enter start port (default 1) : ")
        end_port_input = input(f"{Fore.CYAN}└─▶{Style.RESET_ALL} Enter end port (default 65535) : ")

        start_port = int(start_port_input) if start_port_input else DEFAULT_START_PORT
        end_port = int(end_port_input) if end_port_input else DEFAULT_END_PORT

        if not (1 <= start_port <= end_port <= 65535):
            raise ValueError("Invalid port range")

        start_time = time.time()
        print_status("Initializing scanner...", "info")
        
        open_ports = await scan_all_ports(target_ip, start_port, end_port)

        if not open_ports:
            print_status("No open ports found", "warning")
            return

        print_status(f"Found {len(open_ports)} open ports", "success")
        print_status("Starting vulnerability analysis", "info")
        
        progress_bar = ProgressBar(
            len(open_ports), 
            prefix=f'{Fore.CYAN}Analyzing Vulnerabilities:{Style.RESET_ALL}', 
            suffix='Complete',
            length=40
        )

        async with aiohttp.ClientSession() as session:
            results = await analyze_vulnerabilities(session, open_ports, progress_bar, api_config, target_ip)

        progress_bar.finish()

        table = PrettyTable()
        table.field_names = ["Port", "Service", "Version", "Critical Vulns", "Total Vulns", "Details"]
        
        for result in results:
            service = result['service']
            vulns = result['vulnerabilities']
            critical_vulns = len([v for v in vulns if float(v['cvss'] or 0) >= 7.0])
            
            # Préparer les détails des vulnérabilités critiques
            critical_details = "\n".join([
                f"- {v['title']} (CVSS: {v['cvss']})"
                for v in vulns
                if float(v['cvss'] or 0) >= 7.0
            ][:3])  # Limiter à 3 vulnérabilités critiques
            
            if critical_details:
                critical_details += "\n(+ more...)" if len([v for v in vulns if float(v['cvss'] or 0) >= 7.0]) > 3 else ""
            else:
                critical_details = "No critical vulnerabilities"

            table.add_row([
                f"{Fore.CYAN}{result['port']}{Style.RESET_ALL}",
                f"{Fore.YELLOW}{service['name']}{Style.RESET_ALL}",
                f"{service['product']} {service['version']}",
                f"{Fore.RED}{critical_vulns}{Style.RESET_ALL}" if critical_vulns else f"{Fore.GREEN}0{Style.RESET_ALL}",
                len(vulns),
                critical_details
            ])

        print("\n" + str(table))
        elapsed_time = time.time() - start_time
        print_status(f"Scan completed in {elapsed_time:.2f} seconds", "success")

        # Génération du rapport détaillé
        report_path = f"scan_report_{target_ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(report_path, 'w') as f:
            f.write(f"Vulnerability Scan Report for {target_ip}\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"{'='*80}\n\n")
            
            for result in results:
                service = result['service']
                vulns = result['vulnerabilities']
                
                f.write(f"Port {result['port']} - {service['name']}\n")
                f.write(f"{'='*40}\n")
                f.write(f"Service Details:\n")
                f.write(f"- Product: {service['product']}\n")
                f.write(f"- Version: {service['version']}\n")
                f.write(f"- Extra Info: {service['extrainfo']}\n")
                f.write(f"- CPE: {service['cpe']}\n\n")
                
                if vulns:
                    f.write("Vulnerabilities:\n")
                    for v in sorted(vulns, key=lambda x: float(x['cvss'] or 0), reverse=True):
                        f.write(f"\nID: {v['id']}\n")
                        f.write(f"Title: {v['title']}\n")
                        f.write(f"CVSS Score: {v['cvss']}\n")
                        f.write(f"Description: {v['description']}\n")
                        f.write(f"Published: {v['published']}\n")
                        f.write("References:\n")
                    for ref in v['references']:
                        f.write(f"- {ref}\n")
                        f.write(f"\n{'-'*40}\n")
                else:
                    f.write("No vulnerabilities found.\n\n")
                
                f.write(f"\n{'-'*80}\n")
            
        print_status(f"Detailed report saved to {report_path}", "success")

    except ValueError as ve:
        print_status(f"Configuration error: {ve}", "error")
    except Exception as e:
        print_status(f"An unexpected error occurred: {e}", "error")
        logging.exception("Detailed error information:")

async def export_results_json(results: List[Dict], target_ip: str) -> None:
    """Export scan results to JSON format"""
    output_file = f"scan_results_{target_ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    try:
        with open(output_file, 'w') as f:
            json.dump({
                'target': target_ip,
                'scan_date': datetime.now().isoformat(),
                'results': results
            }, f, indent=2)
        print_status(f"Results exported to {output_file}", "success")
    except Exception as e:
        print_status(f"Error exporting results: {e}", "error")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print_status("\nScan interrupted by user", "warning")
    except Exception as e:
        print_status(f"Fatal error: {e}", "error")
        logging.exception("Detailed error information:")
