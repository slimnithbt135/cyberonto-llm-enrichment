#!/usr/bin/env python3
"""
Hardcoded pattern dictionaries from CyberRule-Enricher.py
Author: Thabet Slimani <thabet.slimani@gmail.com>
"""

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
# Change FROM:
PRIVILEGE_PATTERNS = {
    r'\bauthenticated\b': 'AuthenticatedUser',  # Already good
    r'\badmin\b|\badministrator\b': 'Administrator',  # Already good
    r'\bread.?write\b': 'ReadWriteAccess',  # Change from 'read |write'
    r'\broot\b': 'RootAccess',  # Already good
    r'\bprivileged\b': 'PrivilegedUser',  # Already good
    r'\bsuperuser\b': 'Superuser',  # Already good
    r'\bsystem\b': 'System',  # Already good
    r'\bnetwork\b': 'NetworkAdmin',  # Already good
    r'\bdomain admin\b': 'DomainAdmin',  # Change from 'domain  admin'
    r'\bguest\b': 'Guest',  # Already good
    r'\banonymous\b': 'Anonymous',  # Already good
    r'\bremote user\b': 'RemoteUser',  # Change from 'remote  user'
    r'\blocal user\b': 'LocalUser',  # Change from 'local  user'
    r'\bservice account\b': 'ServiceAccount',  # Change from 'service  account'
    r'\bAPI user\b': 'APIUser',  # Already good
}
