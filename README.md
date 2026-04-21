
![logo1](https://github.com/user-attachments/assets/02f43367-1b7e-42f0-b25c-6ed786079567)

## 🛡️ Disclaimer
*This program is fully capable of breaking the law depending on how it is used. Always ensure you have explicit, written permission from the owner of the device or network you are testing. The author assumes no liability for misuse. Use responsibly.*


**Author SuperSploit core code: Donald Ford aka don970** https://github.com/don970/SuperSploit-updated

**Author for phoneinfoga: Raphaël aka sundowndv** https://github.com/sundowndev/phoneinfoga

**Author for recon-ng: Tim Tomes aka lanmaster53** https://github.com/lanmaster53/recon-ng

**Author for Bettercap: Simone Margaritelli aka evilsocket** https://www.bettercap.org/

# SuperSploit Framework

![logo](https://github.com/don970/SuperSploit-updated/raw/main/assets/logo.png)

**SuperSploit** is a highly optimized, Python 3-based exploitation, reconnaissance, and payload management framework. Built as a lightweight, command-line alternative to heavier GUI-laden platforms, it prioritizes speed, reliability, and a minimal system footprint. 

By offering granular control over modular payloads and integrating advanced staged deployment strategies, SuperSploit provides a highly efficient execution hub for interactive penetration testing and hardware-level attacks.

---

## 🚀 Core Strengths

### 1. Lightweight & Command-Line First
Designed for speed and reliability, the framework avoids the overhead of a graphical user interface. Its terminal-based architecture ensures a minimal footprint, allowing it to run smoothly on constrained environments while offering maximum stability during complex, multi-stage attacks.

### 2. Performance-Optimized Routing
* **O(1) Command Registry:** Moving away from linear parallel lists, SuperSploit utilizes optimized dictionary mappings for command dispatching. This guarantees instant $O(1)$ response times regardless of how many modules or custom tools are loaded.
* **Intelligent I/O & Caching:** Database reads and CVE lookups are cached locally to minimize redundant disk I/O. Output streams are piped directly to `/dev/stdout` to prevent terminal lag during data-heavy payload executions.

### 3. Modular & Staged Execution Engine
* **In-Memory Payload Loading:** Utilizing `importlib.util`, Python exploits are dynamically loaded into isolated memory namespaces. This ensures clean, cache-free execution without permanently writing temporary modules to the source tree.
* **Staged Deployment Logic:** Built to support advanced software architectures, the framework accommodates staged execution logic rather than simple "one-shot" runs, giving operators precise, granular control over payload delivery.
* **Fail-Safe Compilation:** C-based exploits are compiled in real-time with strict execution protocols. A rigid `finally` block guarantees that all compiled binaries (`./exploit_bin`) are safely purged from the disk after execution or upon interruption.

### 4. Zero-Trust Security Validation
* **Hybrid Integrity Checking:** The framework implements a strict zero-trust model before execution. System packages (e.g., Nmap, Bettercap) are verified natively via `dpkg -V`, while internal scripts and downloaded custom binaries are validated using Python's SHA256 hashing against a secured `checksums.json`.
* **Deep Input Sanitization:** All user-provided shell arguments are tokenized using `shlex.split()`, providing POSIX-compliant parsing that completely mitigates arbitrary command injection.

### 5. Advanced Hardware & Reconnaissance Cores
* **BlueDucky Integration:** A specialized subsystem that transforms the host into a malicious Bluetooth HID, allowing for L2CAP connection establishment and raw DuckyScript injection.
* **Automated OSINT:** Integrated wrappers for Nmap, Phoneinfoga, and custom NameSearch scripts automate intelligence gathering, parsing results directly into a structured, trackable target database.

---

## 🗺️ Future Roadmap

SuperSploit is continuously evolving. The following phases outline our path toward building an even more robust, scalable platform:

### Phase 1: Persistence & Workspace Isolation
* **Relational Database Migration:** Transitioning the flat JSON configurations to a lightweight, asynchronous SQLite backend to handle complex queries and larger target datasets.
* **Multi-Tenant Workspaces:** Implementing secure, isolated workspaces to separate targets, environment variables, and activity logs across different engagements.

### Phase 2: Execution Hardening
* **Payload Sandboxing:** Integrating Linux namespaces and `seccomp` profiles to strictly limit the host-level permissions of running exploits, protecting the framework's host machine.
* **Standardized Module API:** Developing an Abstract Base Class (ABC) to enforce consistent `check()`, `run()`, and `cleanup()` interfaces across all future community and custom modules.

### Phase 3: Intelligence & Automation
* **Automated Vulnerability Mapping:** Building a correlation engine that automatically cross-references discovered service versions from the target database against local CVE lists to suggest viable exploits.
* **Expanded HID Capabilities:** Enhancing the Bluetooth subsystem to support complex, multi-stage payloads and interactive feedback loops from compromised devices.

### Phase 4: Interface & Extensibility
* **Dynamic Tab Completion:** Real-time auto-suggest and tab completion for active IPs, exploit paths, and CVE numbers directly within the prompt.
* **RESTful API Wrapper:** Developing a headless API mode to allow SuperSploit to be orchestrated remotely or integrated into automated CI/CD security pipelines.

---

Start screen
![Screenshot at 2025-04-19 17-35-38](https://github.com/user-attachments/assets/43518d6e-d1dc-4894-8e91-46074b1bb1cb)
Viewing dynamic variables
![Screenshot at 2025-04-19 17-39-58](https://github.com/user-attachments/assets/c2dae21d-c71b-47cb-9de3-1015d3439006)
Viewing exploit details
![Screenshot at 2025-04-19 18-05-11](https://github.com/user-attachments/assets/1bb8533e-0aa1-4d25-8615-6fbe452ec678)
Search feature
![Screenshot at 2025-04-19 17-40-13](https://github.com/user-attachments/assets/95f99124-b1e9-4e99-bb12-a8356799583c)
![Screenshot at 2025-04-19 17-40-30](https://github.com/user-attachments/assets/a66e4d10-29b1-4320-9052-b1690a665157)
The search feature can also search for specific items
![Screenshot at 2025-04-19 23-18-47](https://github.com/user-attachments/assets/1c39293f-7cd7-45e1-8828-337bda1e1be2)
The search feature can take multiple arguments to as show in the picture bellow
![Screenshot at 2025-04-19 23-19-27](https://github.com/user-attachments/assets/f1a35fef-bd0d-4633-8389-c65fb1a78521)
Running a exploit
![Screenshot at 2025-04-19 23-10-55](https://github.com/user-attachments/assets/1af60312-db23-4497-bbd4-c709b20e70fc)
