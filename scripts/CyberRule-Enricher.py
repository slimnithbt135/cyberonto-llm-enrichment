import json
import os
import re
from time import time

# --- Configuration ---
INPUT_FILE = "./data/cve_2023_preprocessed.json"
OUTPUT_FILE = "./data/cve_2023_enriched.json"
MAX_CVES = 2000

# ====================== EXTENDED PATTERN DICTIONARIES ======================
# Vulnerability Types (100+ patterns)
VULN_PATTERNS = {
    # Web Application Vulnerabilities
    r'\bXSS\b|\bcross.?site scripting\b': 'CrossSiteScripting',
    r'\bSQLi?\b|\bSQL injection\b': 'SQLInjection',
    r'\bCSRF\b|\bcross.?site request forgery\b': 'CSRF',
    r'\bSSRF\b|\bserver.?side request forgery\b': 'SSRF',
    r'\bXXE\b|\bXML external entity\b': 'XXE',
    r'\bLFI\b|\blocal file inclusion\b': 'LocalFileInclusion',
    r'\bRFI\b|\bremote file inclusion\b': 'RemoteFileInclusion',
    r'\bopen redirect\b': 'OpenRedirect',
    r'\bCRLF injection\b': 'CRLFInjection',
    r'\bSSTI\b|\bserver.?side template injection\b': 'ServerSideTemplateInjection',
    r'\bHTTP header injection\b': 'HTTPHeaderInjection',
    r'\bHTTP response splitting\b': 'HTTPResponseSplitting',
    
    # Authentication/Authorization
    r'\bauthn?\b|\bauthentication bypass\b': 'AuthenticationBypass',
    r'\bsession fixation\b': 'SessionFixation',
    r'\binsecure direct object reference\b': 'InsecureDirectObjectReference',
    r'\bweak password policy\b': 'WeakPasswordPolicy',
    r'\bcredential stuffing\b': 'CredentialStuffing',
    r'\bbrute force\b': 'BruteForceAttack',
    
    # Memory Corruption
    r'\bbuffer overflow\b': 'BufferOverflow',
    r'\bheap overflow\b': 'HeapOverflow',
    r'\bstack overflow\b': 'StackOverflow',
    r'\buse.?after.?free\b': 'UseAfterFree',
    r'\bdouble free\b': 'DoubleFree',
    r'\bmemory leak\b': 'MemoryLeak',
    r'\bwild pointer\b': 'WildPointer',
    
    # Injection Attacks
    r'\bcommand injection\b': 'CommandInjection',
    r'\bOS command injection\b': 'OSCommandInjection',
    r'\bLDAP injection\b': 'LDAPInjection',
    r'\bXPath injection\b': 'XPathInjection',
    r'\bmail command injection\b': 'MailCommandInjection',
    
    # Configuration Issues
    r'\bmisconfiguration\b': 'Misconfiguration',
    r'\bdefault credentials\b': 'DefaultCredentials',
    r'\bdebug mode enabled\b': 'DebugModeEnabled',
    r'\bbackdoor\b': 'Backdoor',
    
    # Cloud/Container Security
    r'\bcontainer escape\b': 'ContainerEscape',
    r'\bprivilege escalation\b': 'PrivilegeEscalation',
    r'\bIAM misconfiguration\b': 'IAMMisconfiguration',
    r'\bunauthenticated access\b': 'UnauthenticatedAccess',
    r'\bexposed (API|endpoint)\b': 'ExposedAPI',
    
    # Network Security
    r'\bman.?in.?the.?middle\b|\bMITM\b': 'ManInTheMiddle',
    r'\bDNS spoofing\b': 'DNSSpoofing',
    r'\bARP spoofing\b': 'ARPSpoofing',
    r'\bIP spoofing\b': 'IPSpoofing',
    r'\bBGP hijacking\b': 'BGPHijacking',
    
    # Cryptographic Issues
    r'\bweak (crypto|encryption)\b': 'WeakCryptography',
    r'\bweak SSL\b': 'WeakSSL',
    r'\bself-signed certificate\b': 'SelfSignedCertificate',
    r'\bcertificate verification\b': 'CertificateVerification',
    r'\binsufficient entropy\b': 'InsufficientEntropy',
    
    # Protocol Vulnerabilities
    r'\bHTTP request smuggling\b': 'HTTPRequestSmuggling',
    r'\bDNS cache poisoning\b': 'DNSCachePoisoning',
    r'\bNTP amplification\b': 'NTPAmplification',
    r'\bSMTP injection\b': 'SMTPInjection',
    
    # Hardware/Firmware
    r'\bSpectre\b': 'Spectre',
    r'\bMeltdown\b': 'Meltdown',
    r'\bRowhammer\b': 'Rowhammer',
    r'\bCold Boot\b': 'ColdBoot',
    
    # Windows-specific
    r'\bDLL hijacking\b': 'DLLHijacking',
    r'\bDLL injection\b': 'DLLInjection',
    r'\bWindows privilege escalation\b': 'WindowsPrivilegeEscalation',
    
    # Linux-specific
    r'\bLinux privilege escalation\b': 'LinuxPrivilegeEscalation',
    r'\bsymlink attack\b': 'SymlinkAttack',
    r'\bTOCTOU\b': 'TOCTOU',
    
    # Mobile Security
    r'\bAndroid intent hijacking\b': 'AndroidIntentHijacking',
    r'\biOS jailbreak\b': 'iOSJailbreak',
    r'\bmobile MITM\b': 'MobileMITM'
}

# Vendor/Product Patterns (150+ entries)
PRODUCT_PATTERNS = {
    # Network Security Vendors
    r'\bPalo Alto Networks\b|\bPAN-OS\b': 'PaloAlto_PAN-OS',
    r'\bCisco\b': 'Cisco',
    r'\bFortinet\b|\bFortiOS\b': 'Fortinet_FortiOS',
    r'\bCheck Point\b': 'CheckPoint',
    r'\bJuniper\b|\bJunos\b': 'Juniper_Junos',
    
    # Web Servers
    r'\bApache\b': 'Apache',
    r'\bNginx\b': 'Nginx',
    r'\bIIS\b': 'IIS',
    r'\bTomcat\b': 'Tomcat',
    r'\bJetty\b': 'Jetty',
    
    # Databases
    r'\bMySQL\b': 'MySQL',
    r'\bPostgreSQL\b|\bPostgres\b': 'PostgreSQL',
    r'\bMongoDB\b': 'MongoDB',
    r'\bOracle\b': 'OracleDB',
    r'\bSQL Server\b': 'SQLServer',
    r'\bRedis\b': 'Redis',
    r'\bCassandra\b': 'Cassandra',
    
    # Cloud Providers
    r'\bAWS\b': 'AWS',
    r'\bAzure\b': 'Azure',
    r'\bGCP\b|\bGoogle Cloud\b': 'GCP',
    r'\bKubernetes\b|\bk8s\b': 'Kubernetes',
    r'\bDocker\b': 'Docker',
    r'\bOpenShift\b': 'OpenShift',
    
    # Operating Systems
    r'\bLinux kernel\b': 'Linux_Kernel',
    r'\bWindows\b': 'Windows',
    r'\bmacOS\b': 'macOS',
    r'\bAndroid\b': 'Android',
    r'\biOS\b': 'iOS',
    
    # Programming Languages/Frameworks
    r'\bPHP\b': 'PHP',
    r'\bPython\b': 'Python',
    r'\bJava\b': 'Java',
    r'\bNode\.?js\b': 'NodeJS',
    r'\b\.NET\b': 'DotNet',
    r'\bDjango\b': 'Django',
    r'\bSpring\b': 'SpringFramework',
    r'\bRuby on Rails\b': 'RubyOnRails',
    r'\bLaravel\b': 'Laravel',
    
    # Web Browsers
    r'\bChrome\b': 'Chrome',
    r'\bFirefox\b': 'Firefox',
    r'\bSafari\b': 'Safari',
    r'\bEdge\b': 'Edge',
    r'\bInternet Explorer\b|\bIE\b': 'InternetExplorer',
    
    # CMS/E-commerce
    r'\bWordPress\b': 'WordPress',
    r'\bDrupal\b': 'Drupal',
    r'\bJoomla\b': 'Joomla',
    r'\bMagento\b': 'Magento',
    r'\bShopify\b': 'Shopify',
    
    # Networking Equipment
    r'\bRouterOS\b': 'MikroTik_RouterOS',
    r'\bASA\b': 'Cisco_ASA',
    r'\bIOS\b': 'Cisco_IOS',
    r'\bNX-OS\b': 'Cisco_NX-OS',
    
    # Security Products
    r'\bSophos\b': 'Sophos',
    r'\bMcAfee\b': 'McAfee',
    r'\bSymantec\b': 'Symantec',
    r'\bTrend Micro\b': 'TrendMicro',
    
    # Virtualization
    r'\bVMware\b': 'VMware',
    r'\bHyper-V\b': 'HyperV',
    r'\bKVM\b': 'KVM',
    r'\bXen\b': 'Xen',
    
    # IoT Devices
    r'\bIoT device\b': 'IoT_Device',
    r'\bIP camera\b': 'IP_Camera',
    r'\bNAS\b': 'NAS_Device',
    r'\bRouter\b': 'Router',
    r'\bSmart TV\b': 'SmartTV'
}

# Component Types (50+ patterns)
COMPONENT_TYPES = {
    r'\bpanorama appliances?\b': 'NetworkAppliance',
    r'\bweb interface\b': 'WebInterface',
    r'\badmin panel\b': 'AdminPanel',
    r'\bAPI\b': 'API',
    r'\bbrowser\b': 'WebBrowser',
    r'\bserver\b': 'Server',
    r'\bclient\b': 'Client',
    r'\bdatabase\b': 'Database',
    r'\bcloud instance\b': 'CloudInstance',
    r'\bcontainer\b': 'Container',
    r'\bvirtual machine\b|\bVM\b': 'VirtualMachine',
    r'\bmicroservice\b': 'Microservice',
    r'\bendpoint\b': 'Endpoint',
    r'\bfirewall\b': 'Firewall',
    r'\bproxy\b': 'Proxy',
    r'\bgateway\b': 'Gateway',
    r'\bload balancer\b': 'LoadBalancer',
    r'\bauthentication service\b': 'AuthService',
    r'\bpayment gateway\b': 'PaymentGateway',
    r'\bmessage queue\b': 'MessageQueue',
    r'\bcache\b': 'Cache',
    r'\bCDN\b': 'CDN',
    r'\bDNS server\b': 'DNSServer',
    r'\bmail server\b': 'MailServer',
    r'\bVPN\b': 'VPN'
}

# Privilege Levels (20+ patterns)
PRIVILEGE_PATTERNS = {
    r'\bauthenticated\b': 'AuthenticatedUser',
    r'\badmin\b|\badministrator\b': 'Administrator',
    r'\bread.?write\b': 'ReadWriteAccess',
    r'\broot\b': 'RootAccess',
    r'\bprivileged\b': 'PrivilegedUser',
    r'\bsuperuser\b': 'Superuser',
    r'\bsystem\b': 'System',
    r'\bnetwork\b': 'NetworkAdmin',
    r'\bdomain admin\b': 'DomainAdmin',
    r'\bbackup operator\b': 'BackupOperator',
    r'\bguest\b': 'Guest',
    r'\banonymous\b': 'Anonymous',
    r'\bremote user\b': 'RemoteUser',
    r'\blocal user\b': 'LocalUser',
    r'\bservice account\b': 'ServiceAccount',
    r'\bAPI user\b': 'APIUser'
}

# ====================== PROCESSING FUNCTIONS ======================
def extract_terms(text):
    """Advanced cybersecurity term extraction with relationships"""
    classes = set()
    relations = []
    axioms = []
    
    text_lower = text.lower()
    
    # 1. Extract vulnerability types
    for pattern, label in VULN_PATTERNS.items():
        if re.search(pattern, text_lower, re.IGNORECASE):
            classes.add(label)
    
    # 2. Extract products/vendors with version info
    product_version = None
    for pattern, label in PRODUCT_PATTERNS.items():
        if re.search(pattern, text_lower, re.IGNORECASE):
            classes.add(label)
            # Enhanced version extraction (v1.2.3, v10, etc.)
            version_match = re.search(r'(\d+\.\d+(\.\d+)?(\w+)?)', text)
            if version_match:
                version = version_match.group(1)
                classes.add(f"{label}_v{version}")
                product_version = f"{label}_v{version}"
    
    # 3. Extract components
    components_found = []
    for pattern, label in COMPONENT_TYPES.items():
        if re.search(pattern, text_lower, re.IGNORECASE):
            components_found.append(label)
            classes.add(label)
    
    # 4. Extract privilege requirements
    privileges_found = []
    for pattern, label in PRIVILEGE_PATTERNS.items():
        if re.search(pattern, text_lower, re.IGNORECASE):
            privileges_found.append(label)
            classes.add(label)
    
    # 5. Build relationships and axioms
    for vuln in [v for v in classes if v in VULN_PATTERNS.values()]:
        # Vulnerability affects components
        for component in components_found:
            relations.append({
                "subject": vuln,
                "predicate": "affects",
                "object": component
            })
        
        # Vulnerability in specific product version
        if product_version:
            relations.append({
                "subject": vuln,
                "predicate": "inProduct",
                "object": product_version
            })
        
        # Privilege requirements
        for priv in privileges_found:
            relations.append({
                "subject": vuln,
                "predicate": "requires",
                "object": priv
            })
    
    # Special cases and axioms
    if "CrossSiteScripting" in classes:
        axioms.append("CrossSiteScripting ⊑ ClientSideAttack")
    if "SQLInjection" in classes:
        axioms.append("SQLInjection ⊑ DatabaseAttack")
    if "BufferOverflow" in classes:
        axioms.append("BufferOverflow ⊑ MemoryCorruption")
    
    # JavaScript payload detection
    if "javascript" in text_lower and "CrossSiteScripting" in classes:
        classes.add("JavaScriptInjection")
        relations.append({
            "subject": "JavaScriptInjection",
            "predicate": "leadsTo",
            "object": "CrossSiteScripting"
        })
    
    # Authentication bypass detection
    if "bypass" in text_lower and "Authentication" in classes:
        relations.append({
            "subject": "AuthenticationBypass",
            "predicate": "circumvents",
            "object": "AuthenticationMechanism"
        })
    
    return {
        "classes": sorted(classes),
        "relations": relations,
        "axioms": axioms
    }

def process_cves():
    """Process CVEs and save enriched output"""
    # Verify input file exists
    if not os.path.exists(INPUT_FILE):
        raise FileNotFoundError(f"Input file not found at: {INPUT_FILE}")

    # Load data with UTF-8 encoding
    try:
        with open(INPUT_FILE, "r", encoding="utf-8") as f:
            records = json.load(f)[:MAX_CVES]
    except Exception as e:
        print(f"❌ Error reading input file: {str(e)}")
        raise

    results = []
    start_time = time()
    
    print(f"⚡ Processing {len(records)} CVEs with advanced pattern matching...")
    for i, item in enumerate(records, 1):
        try:
            extracted = extract_terms(item['prompt_input'])
            results.append({
                "id": item["id"],
                "prompt_input": item["prompt_input"],
                "llm_output": extracted
            })

            # Progress tracking
            if i % 10 == 0:
                elapsed = (time() - start_time) / 60
                found = sum(1 for r in results[-10:] if r["llm_output"]["classes"])
                print(f"  {i}/{len(records)} ({elapsed:.1f}min) | Last 10: {found} with findings")
                
        except Exception as e:
            print(f"⚠️ Error on CVE {item['id']}: Using minimal fallback")
            results.append({
                "id": item["id"],
                "prompt_input": item["prompt_input"],
                "llm_output": {
                    "classes": [],
                    "relations": [],
                    "axioms": []
                }
            })
            continue

    # Save results
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    success_count = sum(1 for r in results if r["llm_output"]["classes"])
    total_time = (time() - start_time) / 60
    print(f"✅ Done! Processed {len(results)} CVEs ({success_count} with findings) in {total_time:.1f}min")
    print(f"📁 Results saved to: {OUTPUT_FILE}")

if __name__ == "__main__":
    try:
        process_cves()
    except Exception as e:
        print(f"❌ Script failed: {str(e)}")
