### Core Philosophy
* **Quality Over Quantity:** SuperSploit is strictly designed to be a stable, lightweight exploit and payload delivery system. It will intentionally avoid becoming a bloated framework packed with hundreds of unusable exploits or heavy dependencies. Every module must be highly reliable, OPSEC-safe, and serve a distinct tactical purpose.

### Phase 1: Execution Hardening & Workspace Isolation
* **Continue payload and exploit development** continue developing and maturing the stager and dynamic in memory payloads adding support for multi arch and moving the away from python.
* **Payload Sandboxing:** Integrating Linux namespaces and `seccomp` profiles to strictly limit the host-level permissions of running exploits, ensuring the framework's host machine remains protected.
* **Execution Pipelining:** Allowing the output of one exploit module to pipeline directly into the execution engine of another for zero-click, multi-stage privilege escalation.

### Phase 2: Advanced Post-Exploitation & Lateral Movement
* **Automated Persistence:** Modules that dynamically detect the target OS and establish reboot-persistent C2 connections (e.g., hidden systemd services, Windows Registry Run keys, WMI event subscriptions).
* **Lateral Movement Engine:** Built-in support for pivoting through compromised hosts using Pass-the-Hash (PtH), SMBExec, or SSH key hijacking to infect adjacent subnet nodes without dropping to disk.
* **Loot Collection & Exfiltration:** Automated harvesting of credentials, SAM hashes, browser cookies, and SSH keys, securely exfiltrated over the TLS C2 socket directly into the framework's SQLite database.

### Phase 3: Next-Gen Evasion & Stealth (OPSEC)
* **Polymorphic Payload Compilation:** Moving beyond Python by integrating a dynamic compiler (e.g., Golang, Rust, or C++) that obfuscates AST, generates random function names, and implements anti-debugging checks on the fly to bypass heuristic EDRs.
* **Alternative C2 Protocols:** Expanding the listener beyond TCP/TLS to support asynchronous, hard-to-detect channels like DNS Tunneling, ICMP payloads, and Domain Fronting via legitimate CDNs.
* **Process Hollowing & Injection:** Implementing native Windows API/Syscall modules for reflective DLL injection and process hollowing to hide malicious threads inside legitimate processes (e.g., `explorer.exe`).

### Phase 4: Team Collaboration & Reporting
* **Lightweight Multi-Player Operation:** Implementing a minimal REST/WebSocket API directly over the existing SQLite database to allow multiple operators to sync session states without introducing heavy external dependencies or database bloat.
* **Automated Penetration Test Reporting:** A module that correlates the SQLite target database, execution logs, and looted credentials to automatically generate formatted PDF/Markdown deliverables mapping exploits to MITRE ATT&CK tactics.
* **Web GUI Interface:** A localized web dashboard providing a visual topology map of the target network and active C2 connections, complementing the terminal interface.
