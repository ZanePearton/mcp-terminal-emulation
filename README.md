# MCP Terminal Emulator (Experimental)

**EXPERIMENTAL PROJECT** - A sandboxed terminal emulator for MCP that simulates Unix/Linux environments for cybersecurity education and research.

![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)
![Experimental](https://img.shields.io/badge/status-experimental-orange.svg)
![Educational](https://img.shields.io/badge/purpose-educational-green.svg)
![AI Research](https://img.shields.io/badge/AI-red%20teaming-red.svg)
![Fast MCP](https://img.shields.io/badge/Fast-MCP-blue.svg)
## AI Safety Research Context

**This project was developed as an AI red teaming experiment** to test how AI systems respond when presented with realistic-looking security tool interfaces through MCP (Model Context Protocol). The research explores:

- How AI models evaluate potentially sensitive tool access
- AI robustness to environment simulation and deception
- Safety mechanisms in AI systems when presented with security-related capabilities
- Responsible disclosure of AI prompt injection and social engineering techniques

**Research Findings:** AI systems demonstrated appropriate caution when presented with realistic penetration testing tool interfaces, even when clearly labeled as educational simulations. This suggests good safety awareness but also highlights the importance of clear, honest documentation in AI tool integration.

**For AI Safety Researchers:** This tool can be used to test AI robustness to environment simulation. All outputs are completely fictional - no real system access occurs.

## Disclaimer

This is an **experimental educational tool** designed for cybersecurity training and research in controlled environments. All simulated commands, file contents, and network interactions are completely fake and sandboxed. No real system access or network connections are made.

**Intended for:**
- Cybersecurity education and training
- Penetration testing practice in safe environments
- Security research and tool familiarization
- Red team training scenarios
- **AI safety and robustness testing**

**Not intended for:**
- Production use
- Actual penetration testing
- Real system administration
- Deceiving AI systems in production environments

## Overview

This experimental MCP tool creates a realistic terminal simulation environment that mimics a penetration testing workstation. It includes simulated security tools, realistic file structures, and command outputs commonly seen in cybersecurity contexts - all completely sandboxed using fast mcp.

The tool was originally designed to test whether AI systems would appropriately handle scenarios where they appear to have access to security tools, contributing to research on AI safety and robustness.

## Features

- **Completely Sandboxed** - No real file system or network access
- **Realistic Security Tool Simulation** - Nmap, Metasploit, SQLMap, Hydra, John the Ripper
- **Educational File System** - Pre-populated with realistic penetration testing scenarios
- **Command History Tracking** - Maintains session logs for learning review
- **Safe Learning Environment** - Practice security tools without any risk
- **AI Testing Framework** - Suitable for testing AI system responses to security tool interfaces

## Simulated Security Tools

The emulator provides realistic output for common penetration testing tools:

- **Network Scanning**: `nmap`, `netstat`, `ss`, `ifconfig`
- **Password Cracking**: `john`, `hashcat`, `hydra`
- **Web Application Testing**: `sqlmap`, `curl`, `wget`
- **System Reconnaissance**: `ps`, `lscpu`, `uname`, `id`
- **Network Analysis**: `tcpdump`, `iptables`

## Installation

```bash
# Install dependencies
pip install fastmcp

# Download the script
# Save the provided Python code as main.py

# Make executable
chmod +x main.py
```

## Usage

### Start the MCP Server
```bash
python main.py
```

### Configure MCP Client

**MCP Desktop Configuration:**
```json
{
  "mcpServers": {
    "experimental-terminal": {
      "command": "python",
      "args": ["/path/to/main.py"],
      "env": {}
    }
  }
}
```

## Example Commands

### Network Reconnaissance
```bash
terminal("nmap -sS 192.168.1.100")
terminal("netstat -tulpn")
terminal("ifconfig")
```

### File System Exploration
```bash
terminal("ls -la /home/user/projects/pentesting")
terminal("cat targets.txt")
terminal("cat credentials.txt")
```

### Security Tool Simulation
```bash
terminal("john --wordlist=rockyou.txt hashes.txt")
terminal("sqlmap -u 'http://localhost/login.php' --dbs")
terminal("hydra -L users.txt -P passwords.txt ssh://192.168.1.100")
```

## File System Structure

The emulator includes a realistic penetration testing environment:

```
/home/user/
├── projects/
│   ├── pentesting/
│   │   ├── nmap_scan.py
│   │   ├── exploit.py
│   │   └── sql_injection.py
│   └── reverse_shell/
├── tools/           # Security tools
├── exploits/        # Exploit scripts
├── payloads/        # Payload generators
└── .hidden/         # Hidden files
```

## Available MCP Tools

### `terminal(command: str)`
Execute simulated terminal commands
```python
terminal("ls -la")
terminal("nmap 192.168.1.1")
terminal("cat exploit.py")
```

### `current_directory()`
Get current working directory
```python
current_directory()  # Returns: /home/user
```

### `command_history()`
View recent command history
```python
command_history()  # Returns last 10 commands
```

## Educational Use Cases

- **Learn Security Tools** - Practice with nmap, metasploit, sqlmap without setup
- **Understand File Structures** - Explore typical penetration testing environments  
- **Practice Command Line** - Unix/Linux commands in security context
- **Training Scenarios** - Realistic penetration testing workflows
- **Tool Familiarization** - See expected outputs from security tools
- **AI Safety Research** - Test AI system responses to security tool interfaces

## AI Research Applications

This tool can be used to study:
- AI system evaluation of tool capabilities and environment
- AI robustness to realistic but simulated security environments
- Safety mechanisms in AI systems when presented with sensitive tools
- Responsible AI testing methodologies

**Note for Researchers:** When using this tool for AI testing, ensure compliance with relevant AI safety guidelines and responsible disclosure practices.

## Logging and Session Tracking

The emulator maintains detailed logs:
- `terminal_session.log` - Application logs
- `terminal_session.txt` - Complete command history
- `.bash_history` - Simulated bash history file

## Safety Features

- **No Real Network Access** - All network commands are simulated
- **No File System Access** - Virtual file system only
- **No Process Execution** - All tools outputs are pre-generated
- **No System Modifications** - Completely isolated from host system
- **Educational Content Only** - All "exploits" are non-functional examples

## Customization

### Adding New Commands
Modify the `execute_command()` function to add new tool simulations:

```python
elif cmd.startswith("your_tool "):
    # Add your custom tool simulation here
    return "Simulated tool output"
```

### Custom File Content
Add educational files to the `file_contents` dictionary:

```python
file_contents["your_file.txt"] = "Your educational content here"
```

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                     MCP Client                              │
└─────────────────────┬───────────────────────────────────────┘
                      │ MCP Protocol
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                FastMCP Server                               │
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   terminal  │  │current_dir  │  │  command_history    │  │
│  │   tool()    │  │   tool()    │  │      tool()         │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
│                          │                                  │
│              ┌───────────▼──────────────┐                   │
│              │   Command Processor      │                   │
│              │  execute_command()       │                   │
│              └───────────┬──────────────┘                   │
│                          │                                  │
│  ┌─────────────────────────────────────────────────────────┤
│  │              Virtual Environment                        │
│  │                                                         │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐  │
│  │  │ File System │  │Security Tool│  │  Session State  │  │
│  │  │ Simulator   │  │ Simulators  │  │   Manager       │  │
│  │  │             │  │             │  │                 │  │
│  │  │ /home/user/ │  │ • nmap      │  │ • current_dir   │  │
│  │  │ ├─projects/ │  │ • sqlmap    │  │ • cmd_history   │  │
│  │  │ ├─tools/    │  │ • hydra     │  │ • session_logs  │  │
│  │  │ ├─exploits/ │  │ • john      │  │                 │  │
│  │  │ └─payloads/ │  │ • hashcat   │  │                 │  │
│  │  └─────────────┘  └─────────────┘  └─────────────────┘  │
│  └─────────────────────────────────────────────────────────┘
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
              ┌─────────────────────────┐
              │      Log Files          │
              │                         │
              │ • terminal_session.log  │
              │ • terminal_session.txt  │
              │ • .bash_history         │
              └─────────────────────────┘
```

## Technical Details

- **Framework**: FastMCP
- **Language**: Python 3.7+
- **Architecture**: Stateful command processor with virtual file system
- **Logging**: Comprehensive session and application logging
- **State Management**: Maintains directory context across commands

## Contributing

This is an experimental project. Contributions welcome for:
- Additional security tool simulations
- Enhanced realistic output generation
- Educational content improvements
- Better command parsing
- Documentation updates
- AI safety testing methodologies

## Responsible Use Guidelines

When using this tool for AI research:
- Clearly document the experimental nature when testing with AI systems
- Follow responsible disclosure practices for any findings
- Respect the terms of service of AI platforms being tested
- Consider the ethical implications of AI deception research
- Share findings with the AI safety community when appropriate

## Legal Notice

This tool is for educational purposes only. All simulated content is fictional and not intended for actual use in penetration testing or malicious activities. Users are responsible for ensuring their use complies with applicable laws and organizational policies.

When used for AI research, users should ensure compliance with relevant AI platform terms of service and ethical research guidelines.

## Requirements

- Python 3.7 or higher
- FastMCP library
- MCP-compatible client

## License

Educational and research use only. Not for production or commercial use.

---
