### Phase 1: Execution Hardening & Workspace Isolation
* **Continue payload and exploit development** continue developing and maturing the stager and dynamic in memory payloads adding support for multi arch and moving the away from python.
* **Payload Sandboxing:** Integrating Linux namespaces and `seccomp` profiles to strictly limit the host-level permissions of running exploits, ensuring the framework's host machine remains protected.

### Phase 2: Automated Attack Chains & Interface
* **Execution Pipelining:** Allowing the output of one exploit module to pipeline directly into the execution engine of another for zero-click, multi-stage privilege escalation.

### Phase 3: Advanced Post-Exploitation & Lateral Movement
* **Automated Persistence:** Modules that dynamically detect the target OS and establish reboot-persistent C2 connections (e.g., hidden systemd services, Windows Registry Run keys, WMI event subscriptions).
* **Lateral Movement Engine:** Built-in support for pivoting through compromised hosts using Pass-the-Hash (PtH), SMBExec, or SSH key hijacking to infect adjacent subnet nodes without dropping to disk.
* **Loot Collection & Exfiltration:** Automated harvesting of credentials, SAM hashes, browser cookies, and SSH keys, securely exfiltrated over the TLS C2 socket directly into the framework's SQLite database.

### Phase 4: Next-Gen Evasion & Stealth (OPSEC)
* **Polymorphic Payload Compilation:** Moving beyond Python by integrating a dynamic compiler (e.g., Golang, Rust, or C++) that obfuscates AST, generates random function names, and implements anti-debugging checks on the fly to bypass heuristic EDRs.
* **Alternative C2 Protocols:** Expanding the listener beyond TCP/TLS to support asynchronous, hard-to-detect channels like DNS Tunneling, ICMP payloads, and Domain Fronting via legitimate CDNs.
* **Process Hollowing & Injection:** Implementing native Windows API/Syscall modules for reflective DLL injection and process hollowing to hide malicious threads inside legitimate processes (e.g., `explorer.exe`).

### Phase 5: Team Collaboration & Reporting
* **Multi-Player Red Teaming:** Evolving the SQLite database into a scalable PostgreSQL backend with a REST/GraphQL API to allow multiple operators to connect their CLI clients to a single, shared session state.
* **Automated Penetration Test Reporting:** A module that correlates the SQLite target database, execution logs, and looted credentials to automatically generate formatted PDF/Markdown deliverables mapping exploits to MITRE ATT&CK tactics.
* **Web GUI Interface:** A localized web dashboard providing a visual topology map of the target network and active C2 connections, complementing the terminal interface.
