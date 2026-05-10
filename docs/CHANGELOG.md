# Changelog

All notable changes to this project will be documented in this file.

## [1.2.10] - 2026-05-25
### Added
- **Extended Port Scope Configuration:** Added support for the `PORT_RANGE` flag in the async port scanner. The scanner now intelligently merges the `PORTS` and `PORT_RANGE` database variables to allow for simultaneous custom lists and specific ranges.
- **Fileless Payload Delivery:** Transformed the payload generator in `exploithandler.py` into a purely in-memory architecture. SuperSploit now automatically formats generated stagers into Base64-encoded Python one-liners, allowing for instant, diskless execution on target machines.
- **Advanced Diagnostic Commentary:** Injected extensive inline debugging notes (`# DEBUG TIP:`) throughout the async port scanner detailing `asyncio` file descriptor constraints, TCP handshake bottlenecks, and socket exception triage.
- **Automated Exploit-to-Payload Linking:** Upgraded the `ExploitHandler` execution logic to automatically detect if `PAYLOAD` is set in the database during exploit execution. If present, the framework seamlessly compiles the payload, caches the encryption key, and starts the C2 listener dynamically before the exploit fires.

### Changed
- **Port Boundary Expansion:** Updated the async port scanner's boundary calculation to support scanning port `0`, officially spanning the entire `0-65535` range.
- **Stale Cache Elimination:** Refactored `host_discovery.py` and `os-fingerprint.py` to load the `data.json` database dynamically at execution time (within `Start.__init__`) rather than at global module import time.
- **Dynamic Port Targeting:** Updated the native `os-fingerprint.py` module to fetch the target port from the database (`R_PORT`) dynamically instead of enforcing a hardcoded port 80 check.
- **JSON Dictionary Optimization:** Simplified target appending logic in both the port scanner and Custom Nmap OS Lookup modules using Python's native `dict.setdefault()`, significantly reducing verbosity and eliminating the risk of `KeyError` crashes.
- **Dual Variable Syntax:** Updated the payload generator and listener to intelligently support both standard (`LHOST`/`LPORT`) and legacy (`L_HOST`/`L_PORT`) variable syntaxes simultaneously to prevent failed reverse shell callbacks.
- **Silent Auto-Generation:** Refined the automated payload compilation workflow to run completely silently in the background, removing unnecessary UI view prompts and keeping the exploit execution sequence completely seamless.

### Fixed
- **Input Fallback Safety:** Hardened the async port scanner's scope generation block. If an invalid or malformed port range is provided, it now gracefully defaults to well-known privileged ports (`1-1024`) instead of crashing or executing an empty scan.
- **OS Fingerprint Accuracy:** Fixed a critical assumption in `Custom_nmap_db_Lookup.py` where closed ports were blindly guessed. The engine now actively scans for verifiable closed TCP (via `RST`) and UDP (via `ICMP Port Unreachable`) ports using random high-port probes, drastically improving the accuracy of T5-T7 and U1 Nmap signature metrics.
- **Session ID Persistence:** Fixed a string-parsing logic bug in `source/main.py` where the framework's unique UUID session ID was failing to save to the database on boot. The `SetV` handler now correctly receives argument lists rather than raw strings, ensuring activity logs accurately track the active session.
- **Listener Port Alignment:** Fixed a configuration key typo in `exploithandler.py` where the background C2 listener was querying `L_PORT` instead of `LPORT`, causing it to listen on port `4444` while payloads were generated for `5000`. The payload generator and listener are now perfectly synchronized.
- **Dangling Listener Cleanup:** Fixed a bug where running an exploit multiple times in a single session resulted in an `[Errno 48] Address already in use` crash. The `ExploitHandler` now tracks active daemon sockets and cleanly terminates them before binding new listeners, preventing port contention and mismatched XOR keys.
- **Stager Execution Bug:** Added the missing `Start()` initialization call to the bottom of the `stager.py` payload. The fileless Stage 1 stager now automatically executes upon being decoded in memory on the target.
- **Loopback IP Trap:** Implemented a pre-generation sanity check that warns users if they accidentally attempt to map a reverse shell back to a local loopback or wildcard address (`127.0.0.1` or `0.0.0.0`).

## [1.2.9] - 2026-05-20
### Added
- **Advanced Nmap OS Fingerprinting:** Implemented a highly accurate, pure-Python OS fingerprinting engine (`Custom_nmap_db_Lookup.py`) using Scapy. Replicates Nmap's 13 specific probes (SEQ, OPS, WIN, ECN, T1-T7, U1, IE) and correlates raw responses against `nmap-os-db.txt` using official generation match points and weight formulas.
- **Concurrent Network Probing:** Upgraded the OS fingerprinting engine to utilize `asyncio` combined with a `ThreadPoolExecutor` to execute blocking Scapy network probes concurrently, drastically accelerating OS detection.
- **Heuristic Service Detection:** Introduced a `ServiceDetector` class to the native async port scanner, providing active protocol signature matching (e.g., `SSH-2.0`, `HTTP/1.1`) and intelligent standard-port fallbacks.
- **Custom Port Scopes:** Added support for specifying custom port sweeps in the async port scanner utilizing the `PORTS` global variable (supports comma-separated lists and ranges like `80,443,8000-8080`).

### Changed
- **Dynamic Variable Loading:** Refactored the async port scanner to load `data.json` dynamically at execution time rather than at module import time, eliminating stale memory cache bugs when users update global variables.
- **Centralized Target Persistence:** Upgraded both the port scanner and OS fingerprinting modules to natively append their findings (open ports, detected services, and matched OS fingerprints) directly to the nested `TARGETS` dictionary in `targets.json` without destroying or overwriting existing host entries.
- **Educational Code Documentation:** Added deep, technically rigorous inline docstrings across `host_discovery.py`, `port_scanner.py`, and `Custom_nmap_db_Lookup.py` explaining raw socket behavior, OSI network layers, `asyncio` limitations, and packet formulation logic.

### Fixed
- **Module Metadata Integration:** Fixed a critical `IndexError` crash in the `recon_engien.py` loader by injecting the missing `#!#!#!` framework metadata block into the new OS fingerprint module.
- **Scapy Parsing Exception:** Resolved a `Layer [IP] not found` exception in the OS fingerprint module's ICMP Echo (IE) probe by validating packet request IDs directly instead of improperly digging into Echo Reply payloads.
- **Connection Reset Handling:** Added `ConnectionResetError` catching in the port scanner to prevent mid-handshake firewall `RST` packets from crashing the asynchronous event loop.

## [1.2.8] - 2026-05-15
### Added
- **Recon Documentation:** Created a dedicated and highly detailed help page for reconnaissance modules (`.data/.help/recon`).
- **Feature Documentation:** Documented new core framework features in the help files, including automated post-recon exploit suggestions (`auto_suggest`), native background raw TCP listeners (`listener`), and comprehensive target database management.

### Changed
- **Help System Overhaul:** Completely rewrote and stylized the core help files (`all`, `show`, `search`, `use`, `set`, and `modules`). Introduced cleaner visual formatting, emoji headers, better sectioning, and more detailed command usage examples.

### Fixed
- **Search Output Clutter:** Updated `source/core/search.py` to correctly filter out and hide `__pycache__` directories when searching for exploits, payloads, and recon modules.
- **Code Cleanup:** Fixed a malformed and duplicate class definition/import statement at the top of `source/core/search.py`.

## [1.2.7] - 2026-05-10
### Added
- **Native Host Discovery:** Implemented `recon/native-discovery/host_discovery.py` using raw sockets and Scapy to perform hyper-fast asynchronous Layer 2 (ARP) and Layer 3 (ICMP) ping sweeps, completely replacing Nmap's `-sn` capabilities.
- **Async Port Scanner:** Upgraded the native port scanner in `recon/native-portscan/port_scanner.py` to utilize Python's `asyncio` and `Semaphore` for non-blocking, concurrent network mapping and dynamic active banner grabbing.

### Changed
- **Dedicated Targets Database:** Separated discovered network targets from the main framework configuration (`data.json`) into a dedicated `targets.json` database. Updated `DatabaseManagment` in `source/core/database.py` and the host discovery module to seamlessly read from and write to this new structure.

### Fixed
- **Recon Module Caching Bug:** Fixed an issue in `source/core/recon_engien.py` where switching recon modules would execute the previously loaded module. The database configuration fetch (`DatabaseManagment.get()`) was moved inside the `Recon.__init__` method to guarantee the latest module path is pulled on every execution.

## [1.2.6] - 2026-05-08
### Added
- **Recon Commands in Help:** Added the `recon` command to `.data/.help/all` and created `.data/.help/recon` help documentation.
- **Recon Support in Search:** Added the `recon` category to the `search` command to search for recon modules in `source/core/search.py`.
- **Recon Selection in Use:** Updated the `use` command in `source/core/use.py` to allow selecting and setting `RECON_NAME` and `RECON_PATH` when using recon modules.
- **Port Scanner Recon Module:** Added a new native port scanner module in `recon/native-portscan/port_scanner.py`.
- **Recon Logging:** Created a new `recon_activity.log` file with rotation logic for reconnaissance sessions in `source/core/logger.py`.
- **Recon Engine Execution:** Implemented the actual execution capability using a dynamically loaded Python module for recon scripts in `source/core/recon_engien.py` and linked it via the `Input` handler.

### Changed
- **Database Recon Management:** Extended `DatabaseManagment` in `source/core/database.py` with `UpdateReconDB` and `_reconDB` to map and parse recon directories.
- **Configuration Schema:** Added `dev_mode`, `sessionId`, `recon_name`, and `recon_path` variables to the main DB configuration loader.
- **OS Fingerprint Script:** Migrated `os-fingerprint.py` from `source/core/recon/` to `recon/os-fingerprinting/` and enhanced the start script implementation.

### Fixed
- **Python Module Loader Issue:** Corrected typos (`biypass` -> `bypass`, `spec_from_fle_location` -> `spec_from_file_location`) when executing Python payloads dynamically via `importlib` in `source/core/exploithandler.py`.
- **Installer Script Fix:** Corrected an issue where `supersploit` would fail directly without `sudo` in `install.sh` and `start.sh` due to permission checks.

## [1.2.5] - 2026-05-02
### Added
- **Advanced OS Fingerprinting:** Expanded the network fingerprint dictionary in `os-fingerprint.py` to capture deep IP and TCP layer metrics (TOS, IHL, fragmentation, seq/ack numbers) and explicit TCP option ordering (`options_order`) for improved identification accuracy.

### Changed
- **Documentation:** Added comprehensive docstrings and inline comments to the `Recon` class in `source/core/recon_engien.py` to improve maintainability and clarify dynamic execution logic.

### Fixed
- **Target Parsing:** Integrated `urllib.parse.urlparse` in the OS fingerprint module to safely sanitize URLs and strip ports from `R_HOST` before executing Scapy network probes.
- **Graceful Error Handling:** Added explicit exception catching for `PermissionError` and `Scapy_Exception` in `os-fingerprint.py` to warn users about missing root privileges instead of crashing the engine with stack traces.

## [1.2.4] - 2026-04-29
### Added
- **OS Fingerprinting Engine:** Introduced modular `OSFingerprintEngine` class for active OS detection via TCP fingerprinting with Scapy integration. Supports remote signature database queries and session-based logging.
- **Development**: Introduced a `DEVMODE` toggle in `start.sh` to allow running the application directly from the source directory.
- **Development**: Added basic support for mac-os development.
- **Documentation**: Added comprehensive module, class, and method docstrings to `source/core/database.py`.
- **Documentation**: Added inline comments to clarify YAML metadata extraction, file traversals, and JSON database modifications.
- **Documentation**: Updated exploit integration documentation with complete working examples demonstrating variable retrieval, socket usage, and error handling patterns.

### Changed
- **Help System Redesign:** Completely restructured help documentation with ASCII art branding, organized command categories, and improved clarity for end-users.
- **Command Simplification:** Eliminated command categories (`recon_cmds`, `wifi_cmds`, `bt_cmds`) from the input handler to streamline core functionality and reduce complexity.
- **Architecture:** Refactored the input handler to remove verbose command routing, enabling a future plugin-based reconnaissance system.
- **Code Style**: Refactored boolean conditional prompts in `source/core/exploithandler.py` to be more Pythonic.
- **Session Logging:** Continued session-based activity tracking with framework launch events logged to `activity.log`.

### Deprecated
- **Reconnaissance Module:** The legacy `reconCore` module is deprecated in favor of future modular recon plugins. This includes Bluetooth utilities, external tool wrappers, and network reconnaissance functions.

### Removed
- **BREAKING**: The following commands are no longer available: `ducky`, `ranger`, `recon`, `scan`, `full-scan`, `custom-scan`, `get-targets`, `import-targets`, `view-targets`, `port-scan`.
- **Bluetooth Module:** Removed `BlueDucky.py` and all HID keyboard emulation utilities.
- **External Tool Wrappers:** Removed `phoneinfoga`, `namesearch`, and `bettercap` wrapper classes.
- **Network Reconnaissance:** Removed `NmapWrapper` class and associated nmap scanning functionality.
- **Legacy Data Files:** Removed nmap targets (`target.json`), security checksums (`checksums.json`), and deprecated help files.
- Purged `__pycache__` directories for removed modules to maintain a clean repository state.

### Fixed
- **Critical Bug:** Fixed a Python module caching bug in `source/core/exploithandler.py` by implementing dynamic module loading (`importlib.util`) to bypass `sys.modules` cache retention.
- Corrected the `except` block syntax in `exploithandler.py` from `except Exception or KeyboardInterrupt:` to `except (Exception, KeyboardInterrupt):`.
- Fixed invalid exception handling syntax and exception-swallowing `return` statements in the Python exploit module runner's `finally` block.
- Implemented cleanup for the temporary `exec_temp.py` file in `exploithandler.py` to prevent leftover files.
- Removed redundant `file.close()` calls within `with` statement context managers.
- Removed an unnecessary `chmod +x` subprocess call after `gcc` compilation for C exploits.
- Cleaned up logic for executing dynamically loaded Python exploit modules with and without arguments.
- **Input Handling**: Fixed an issue where trailing spaces were not properly removed from user input by changing `lstrip` to `rstrip` in `inputHandler.py`.

### Security
- Added system package integrity verification for `recon-ng` using the `validator` module (`inputHandler.py`).

---

## [version 1.2.3] - 2026-04-21
### Enhancements
* **Command Handler Refactoring:** Streamlined WiFi scanning commands by removing deprecated target management workflow. Unified scanning interface with simplified `scan` and `full-scan` commands.
* **External Tools Modernization:** Updated external tool classes (`bettercap`, `namesearch`, `phoneinfoga`) with improved error handling, better prompt integration, and consistent code patterns.
* **Debug and Info Commands:** Added new diagnostic commands `debugdb` (displays full database memory cache) and `update-info` (updates exploit cache) for enhanced troubleshooting.
* **Input Handler Improvements:** Refactored input handler to use `NmapWrapper` directly instead of legacy nmap module imports with proper error handling.

### New Features
* **Diagnostic Commands:** Implemented `debugdb` command to print full database memory cache for debugging purposes.
* **Cache Update Command:** Added `update-info` command to manually trigger exploit cache updates.
* **Info Display Command:** Added `info` command for displaying current exploit details in the CLI.
* **Enhanced NmapWrapper:** Improved network scanning with better target range formatting and verification.

### Bug Fixes
* **Database Method Signatures:** Fixed `DatabaseManagment.Debug()` method to properly accept optional data parameter.
* **ExploitCache Update Method:** Fixed `ExploitCache.update()` to accept optional parameter for consistent API usage.
* **External Tool Module Imports:** Cleaned up external tools module initialization by removing stale imports.
* **Network Recon Import Issues:** Fixed NetworkRecon module initialization to use direct `NmapWrapper` import.
* **Command Registration:** Fixed various command registrations in input handler that were failing due to incorrect method signatures.

### Code Quality
* **Removed Deprecated Features:** Eliminated old target management commands (`get-targets`, `import-targets`, `view-targets`, `view-targets-v`, `port-scan`, `scan-target`) that are now consolidated into simplified scanning interface.
* **Module Cleanup:** Removed unused `wireshark.py` and cleaned up external tools `__init__.py` for better maintainability.
* **Improved Error Handling:** Enhanced subprocess error handling and verification checks in network reconnaissance tools.
* **Test Exploit Updates:** Updated test exploit metadata with proper CVE format and enhanced description.
* **Payload Refinements:** Updated `exec_temp.py` with improved SQL injection test exploit demonstrating command injection payloads.

### Maintenance
* **Help Documentation:** Updated help files to reflect new command structure with `scan` and `full-scan` replacements.
* **Code Refactoring:** Reorganized external tool implementations for consistency and maintainability.
* **Activity Logging:** Continued operational logging and tracking of framework execution sessions.

---

## [version 1.2.2] - 2026-04-21
### Enhancements
* **Python Exploit Handler Refactoring:** Restructured `exploithandler.py` with improved metadata handling using delimiter-based parsing (`#!#!#!`).
* **Temporary File Execution:** Implemented cleaner temporary file handling for exploit execution with consistent path management via `exec_temp.py`.
* **Module Execution Improvements:** Enhanced dynamic module loading with better file cleanup and metadata separation.
* **Network Information Gathering:** Replaced subprocess-based network detection in `inputHandler.py` with efficient `psutil` library integration for improved reliability and cross-platform compatibility.

### New Features
* **Test Exploit Framework:** Added new test exploit (`exploits/test/test.py`) demonstrating the new metadata delimiter system for exploit documentation.
* **Enhanced Network Detection:** Implemented smarter IPv4 address detection that filters out loopback addresses and properly retrieves network interface information.

### Bug Fixes
* **Handler Initialization:** Fixed database initialization in exploit handler with proper `DatabaseManagment.get()` calls.
* **Argument Parsing:** Improved argument parsing and shell command construction in Python exploit execution.
* **Network Information Retrieval:** Fixed `get_network_info()` in `inputHandler.py` to reliably detect non-loopback IPv4 addresses across different system configurations.

---

## [version 1.2.1] - 2026-04-21
### Bug Fixes
* **Missing Functions Resolution:** Fixed critical issues with missing functions that were causing execution failures.
* **Code Refactoring:** Optimized `search.py` and `exploithandler.py` with streamlined logic and reduced redundancy.
* **Input Handler Improvements:** Enhanced `inputHandler.py` with better error handling and validation.

### Code Quality
* **Database Optimization:** Further refined `database.py` with improved caching mechanisms and reduced complexity (225 lines refactored).
* **Exploit Cleanup:** Removed obsolete exploit files for Windows, routers, and deprecated Android tools that were no longer maintained.
* **Chrome Exploit Updates:** Updated Chrome OS privilege escalation exploit with refined execution logic.

### Maintenance
* **Asset Cleanup:** Removed outdated PDF and image assets from the assets folder for better repository hygiene.
* **Activity Logging:** Enhanced operational logging in `activity.log` to track framework execution more reliably.
* **Configuration Updates:** Updated `.data/.config/data.json` with improved settings management.

---

version 1.2.0

## [Core Updates & Refactoring]
### I/O & Performance Optimizations (Bottleneck Fixes)
* **Database I/O Reduction:** Updated `getCVE` in `database.py` to cache results locally. It now returns the CVE immediately if present, preventing redundant disk reads on the exploit file during subsequent calls.
* **Streamlined Standard Output:** Refactored `ToStdOut.py` to write directly to `/dev/stdout` instead of using the standard `print()` function, handling formatting and decoding on the fly to prevent output-heavy payloads from lagging the terminal.
* **Silent Error Handling:** Reworked `errors.py` to dump stack traces silently to `.data/.errors/error.log` without interfering with active program execution or disrupting the CLI flow.

### Centralized Caching & Data Management (`database.py`)
* **In-Memory Exploit Location Cache:** Implemented centralized in-memory caching system for exploit locations and payloads to eliminate redundant file system traversals and significantly improve lookup performance across framework operations.
* **Central Database Architecture:** Transitioned to a unified central database for managing all exploit metadata, locations, and associated payloads. This centralized approach ensures consistency across the framework and reduces data fragmentation.
* **Optimized Cache Invalidation:** Integrated smart cache invalidation mechanisms that maintain data freshness while minimizing disk I/O operations.

### Execution Engine Enhancements (`exploithandler.py`)
* **Dynamic Python Modules:** Added the ability to load and run Python exploits directly into memory as dynamic modules (`importlib.util`). This prevents polluting source folders or causing cache bugs, executing the `exploit()` function directly.
* **Bash Return State Auditing:** Updated the `sh` execution handler to strictly evaluate shell return codes, properly distinguishing between successful runs and failures.
* **C-Compilation Safety:** Added real-time GCC compilation for C exploits with an automatic, fail-safe cleanup mechanism. The compiled `./exploit_bin` is reliably removed after execution, even if a crash or interrupt occurs.
* **Terminal Parsing:** Added `findTerm()` in the database manager to dynamically verify available terminal programs against `/bin` for the threaded exploit handlers.

## [New Features]
### Activity Logging System (`logger.py`)
* **Operational Auditing:** Separated debugging errors from operational logs. Created a dedicated `activity.log` to track exactly which exploits were run, when, and against which targets.
* **Session ID Tracking:** Integrated an 8-character hex Session ID (via `uuid`) generated upon framework launch. All exploit executions are tied to this ID, making it easy to track the flow of a single session.
* **Staged Initialization:** Added a `start_session()` hook that prints a clear demarcation line in the log file every time the framework is booted up.
* **Verbose Arguments Toggle:** Added a `VERBOSE_LOGGING` flag to the database key map. When toggled on, the framework securely dumps the exact command-line arguments and options passed to scripts and binaries into the log.
* **Zero-Lock Log Rotation:** Implemented a native, footprint-conscious log rotation script. If `activity.log` exceeds 5MB, it is instantly archived with a timestamp using `os.rename`, preventing locking issues and keeping the tool lightweight.

### Modular Help Architecture (`help.py`)
* **File-Based Documentation:** Removed hardcoded help strings from the core logic. Help documentation is now pulled dynamically from modular text files stored in `.data/.help/` (e.g., `main`, `set`, `search`).
* **Path Sanitization:** Integrated strict input sanitization (`os.path.basename`) on user topic requests to prevent directory traversal exploits when querying help files.
* **Improved Topic Handling:** Added error handling for missing help topics, defaulting to "all" help file when no topic is specified. Updated help directory path for consistency.

## [Bug Fixes]
### Execution Engine Enhancements (`exploithandler.py`)
* **Method Reordering:** Corrected the order of `sh` and `c` handler methods to match their intended functionality.
* **Enhanced Return Code Auditing:** Updated bash and Python script execution to properly evaluate return codes, distinguishing between successful runs and failures.
* **Improved C Compilation Logging:** Separated logging for C compilation and execution phases, with better error reporting using the Error class.
* **Dynamic Module Execution:** Enhanced Python module loading with proper success/failure logging based on return codes.

### Security and Stability Updates
* **Comprehensive Security Review:** Conducted full framework security audit and implemented stability improvements across all core modules.
* **Input Validation:** Strengthened input sanitization and validation throughout the codebase.
* **Error Handling:** Improved error logging and handling mechanisms to prevent crashes and improve user experience.

### General Improvements
* **Typo Corrections:** Fixed typos in `main.py`, `set.py`, `exploitHandler.py`, and other files.
* **Author Attribution:** Added proper citations for external tool authors (phoneinfoga, recon-ng, Bettercap) in documentation and code comments.
