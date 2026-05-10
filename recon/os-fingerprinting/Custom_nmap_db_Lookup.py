import asyncio
import concurrent.futures
import logging
import os
import json
import re
import time
import math
import random
from scapy.all import IP, TCP, UDP, ICMP, sr1, sr, conf

# --- Framework Integration ---
# Suppress Scapy's verbose output and set up logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
conf.verb = 0

# --- Database Paths ---
install_location = f'{os.getenv("HOME")}/.SuperSploit'
path_to_db_config = f"{install_location}/.data/.config/data.json"
path_to_nmap_db = f"{install_location}/.data/.config/nmap-os-db.txt"
path_to_targets = f"{install_location}/.data/.config/targets.json"

# ---------------------------------------------------------
# 1. NMAP MATCH POINTS (WEIGHTS)
# ---------------------------------------------------------
MATCH_POINTS = {
    "SEQ": {"SP": 25, "GCD": 75, "ISR": 25, "TI": 100, "CI": 50, "II": 100, "SS": 80, "TS": 100},
    "OPS": {"O1": 20, "O2": 20, "O3": 20, "O4": 20, "O5": 20, "O6": 20},
    "WIN": {"W1": 15, "W2": 15, "W3": 15, "W4": 15, "W5": 15, "W6": 15},
    "ECN": {"R": 100, "DF": 20, "T": 15, "TG": 15, "W": 15, "O": 15, "CC": 100, "Q": 20},
    "T1":  {"R": 100, "DF": 20, "T": 15, "TG": 15, "S": 20, "A": 20, "F": 30, "RD": 20, "Q": 20},
    "T2":  {"R": 80,  "DF": 20, "T": 15, "TG": 15, "W": 25, "S": 20, "A": 20, "F": 30, "O": 10, "RD": 20, "Q": 20},
    "T3":  {"R": 80,  "DF": 20, "T": 15, "TG": 15, "W": 25, "S": 20, "A": 20, "F": 30, "O": 10, "RD": 20, "Q": 20},
    "T4":  {"R": 100, "DF": 20, "T": 15, "TG": 15, "W": 25, "S": 20, "A": 20, "F": 30, "O": 10, "RD": 20, "Q": 20},
    "T5":  {"R": 100, "DF": 20, "T": 15, "TG": 15, "W": 25, "S": 20, "A": 20, "F": 30, "O": 10, "RD": 20, "Q": 20},
    "T6":  {"R": 100, "DF": 20, "T": 15, "TG": 15, "W": 25, "S": 20, "A": 20, "F": 30, "O": 10, "RD": 20, "Q": 20},
    "T7":  {"R": 80,  "DF": 20, "T": 15, "TG": 15, "W": 25, "S": 20, "A": 20, "F": 30, "O": 10, "RD": 20, "Q": 20},
    "U1":  {"R": 50,  "DF": 20, "T": 15, "TG": 15, "IPL": 100, "UN": 100, "RIPL": 100, "RID": 100, "RIPCK": 100, "RUCK": 50, "RUD": 100},
    "IE":  {"R": 50,  "DFI": 40, "T": 15, "TG": 15, "CD": 100}
}


class OSFingerprintEngine:
    """
    Executes Nmap-style OS Fingerprinting Probes using Scapy.
    Requires an open TCP port and a closed TCP port to run all tests accurately.
    """
    def __init__(self, target_ip: str, open_tcp: int, closed_tcp: int, closed_udp: int = 31337):
        self.target = target_ip
        self.open_tcp = open_tcp
        self.closed_tcp = closed_tcp
        self.closed_udp = closed_udp
        self.results = {}

    def run_all_probes(self):
        """Executes all probe types concurrently using asyncio."""
        logging.info(f"[*] Starting OS Fingerprint against {self.target}")
        return asyncio.run(self._async_run_all_probes())

    async def _async_run_all_probes(self):
        loop = asyncio.get_running_loop()
        # Use a ThreadPoolExecutor to run blocking Scapy functions concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
            tasks = [
                loop.run_in_executor(pool, self._probe_seq_ops_win),
                loop.run_in_executor(pool, self._probe_ecn),
                loop.run_in_executor(pool, self._probe_t1_t7),
                loop.run_in_executor(pool, self._probe_u1),
                loop.run_in_executor(pool, self._probe_ie)
            ]
            await asyncio.gather(*tasks)
        return self.results

    def _parse_response(self, pkt, probe_name):
        """Helper to parse common TCP/IP header fields from a response packet."""
        if not pkt:
            return {"R": "N"}

        resp = {"R": "Y"}
        if pkt.haslayer(IP):
            resp["DF"] = "Y" if pkt[IP].flags.DF else "N"
            resp["T"] = hex(pkt[IP].ttl)[2:].upper()
        if pkt.haslayer(TCP):
            resp["W"] = hex(pkt[TCP].window)[2:].upper()
            # Simplified TCP options parsing
            opt_str = "".join([o[0][0] for o in pkt[TCP].options if o[0] != 'EOL'])
            if probe_name.startswith("T"):
                resp["O"] = opt_str
            # Flags
            flags = pkt[TCP].flags
            resp["S"] = "S" if flags.S else ""
            resp["A"] = "A" if flags.A else ""
            # ... add other flags as needed
        return resp

    def _probe_seq_ops_win(self):
        """Sends 6 TCP SYN packets to an open port to test SEQ, OPS, and WIN."""
        logging.info("[*] Sending SEQ/OPS/WIN Probes (6 packets)...")
        opts = [
            [('WScale', 10), ('NOP', None), ('MSS', 1460), ('Timestamp', (0xFFFFFFFF, 0)), ('SAckOK', '')],
            [('MSS', 1400), ('WScale', 0), ('SAckOK', ''), ('Timestamp', (0xFFFFFFFF, 0)), ('EOL', None)],
            [('Timestamp', (0xFFFFFFFF, 0)), ('NOP', None), ('NOP', None), ('WScale', 5), ('NOP', None), ('MSS', 1460)],
            [('SAckOK', ''), ('Timestamp', (0xFFFFFFFF, 0)), ('WScale', 10), ('EOL', None)],
            [('MSS', 536), ('SAckOK', ''), ('Timestamp', (0xFFFFFFFF, 0)), ('WScale', 10), ('EOL', None)],
            [('MSS', 265), ('SAckOK', ''), ('Timestamp', (0xFFFFFFFF, 0)), ('WScale', 10)],
        ]
        wins = [1, 63, 4, 4, 16, 512]
        responses = []

        for i in range(6):
            p = IP(dst=self.target, id=i + 1) / TCP(dport=self.open_tcp, flags="S", window=wins[i], options=opts[i])
            # Added verbose=0 to sr1 so Scapy doesn't flood your console output
            ans = sr1(p, timeout=2, verbose=0)
            responses.append(ans)
            time.sleep(0.1)

        # Safely initialize keys without wiping out existing state from other concurrent probes
        self.results.setdefault("OPS", {})
        self.results.setdefault("WIN", {})
        self.results.setdefault("SEQ", {})
        self.results.setdefault("IPID", {})  # Adding IPID tracking, crucial for native OS fingerprinting

        # Parse responses and capture ALL required fingerprinting data
        for i, r in enumerate(responses):
            if r and r.haslayer(TCP):
                # 1. Window size capture
                self.results["WIN"][f"W{i + 1}"] = hex(r[TCP].window)[2:].upper()

                # 2. Options string extraction
                opt_str = "".join([o[0][0] for o in r[TCP].options if o[0] != 'EOL'])
                self.results["OPS"][f"O{i + 1}"] = opt_str

                # 3. FIX: Actually extract and save the sequence numbers!
                self.results["SEQ"][f"S{i + 1}"] = r[TCP].seq

                # 4. FIX: Extract IP ID for sequence generation analysis
                if r.haslayer(IP):
                    self.results["IPID"][f"I{i + 1}"] = r[IP].id

    def _probe_ecn(self):
        """Sends a TCP SYN/ECN packet to an open port."""
        logging.info("[*] Sending ECN Probe...")
        p = IP(dst=self.target) / TCP(dport=self.open_tcp, flags="SEC", window=3, options=[('WScale', 10), ('NOP', None), ('MSS', 1460), ('SAckOK', '')])
        ans = sr1(p, timeout=2)
        self.results["ECN"] = self._parse_response(ans, "ECN")
        if ans and ans.haslayer(TCP):
            self.results["ECN"]["CC"] = "Y" if 'E' in str(ans[TCP].flags) else "N"

    def _probe_t1_t7(self):
        """Sends the 7 TCP probes to open and closed ports."""
        logging.info("[*] Sending TCP T1-T7 Probes...")
        probes = {
            "T1": IP(dst=self.target) / TCP(dport=self.open_tcp, flags="S", options=[('WScale', 10), ('NOP', None), ('MSS', 1460), ('Timestamp', (0xFFFFFFFF, 0)), ('SAckOK', '')]),
            "T2": IP(dst=self.target) / TCP(dport=self.open_tcp, flags=""),
            "T3": IP(dst=self.target) / TCP(dport=self.open_tcp, flags="SFUP"),
            "T4": IP(dst=self.target) / TCP(dport=self.open_tcp, flags="A"),
            "T5": IP(dst=self.target) / TCP(dport=self.closed_tcp, flags="S"),
            "T6": IP(dst=self.target) / TCP(dport=self.closed_tcp, flags="A"),
            "T7": IP(dst=self.target) / TCP(dport=self.closed_tcp, flags="FPU"),
        }
        for name, pkt in probes.items():
            ans = sr1(pkt, timeout=2)
            self.results[name] = self._parse_response(ans, name)

    def _probe_u1(self):
        """Sends a UDP packet to a closed port."""
        logging.info("[*] Sending UDP U1 Probe...")
        p = IP(dst=self.target, id=0x1042) / UDP(dport=self.closed_udp) / (b"C" * 300)
        ans = sr1(p, timeout=3)
        if ans and ans.haslayer(ICMP) and ans[ICMP].type == 3 and ans[ICMP].code == 3:
            self.results["U1"] = {"R": "Y"}
            if ans.haslayer(IP):
                self.results["U1"]["DF"] = "Y" if ans[IP].flags.DF else "N"
                self.results["U1"]["T"] = hex(ans[IP].ttl)[2:].upper()
            # Nmap checks the returned IP packet inside the ICMP payload. This is a simplification.
            if ICMP in ans and IP in ans[ICMP].payload:
                 self.results["U1"]["RIPL"] = "G" # Generic until parsed
        else:
            self.results["U1"] = {"R": "N"}

    def _probe_ie(self):
        """Sends two ICMP Echo probes."""
        logging.info("[*] Sending ICMP IE Probes...")
        p1 = IP(dst=self.target, id=123, flags="DF") / ICMP(type=8, code=9, seq=295, id=123)
        p2 = IP(dst=self.target, id=124, tos=4) / ICMP(type=8, code=0, seq=296, id=124)
        ans, unans = sr([p1, p2], timeout=2)

        if not ans:
            self.results["IE"] = {"R": "N"}
            return

        self.results["IE"] = {"R": "Y"}
        # DFI (Don't Fragment Echo) - checks if DF bit is respected
        # Simplified: check if any response came back for the DF-set packet
        if any(r[1].haslayer(IP) and r[0].id == 123 for r in ans):
             self.results["IE"]["DFI"] = "Y"
        else:
             self.results["IE"]["DFI"] = "N"


class NmapDBMatcher:
    """
    Scores the results generated by OSFingerprintEngine against nmap-os-db.txt
    using the exact weighting formulas.
    """
    def __init__(self, nmap_db_path: str):
        self.nmap_db_path = nmap_db_path
        self.fingerprints = []
        self.parse_db()

    def parse_db(self):
        """Load nmap-os-db.txt into memory as a list of fingerprint dictionaries."""
        try:
            with open(self.nmap_db_path, 'r', encoding='utf-8', errors='ignore') as f:
                current_fp = None
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#') or line.startswith('MatchPoints'):
                        continue

                    if line.startswith('Fingerprint '):
                        if current_fp:
                            self.fingerprints.append(current_fp)
                        os_name = line[len('Fingerprint '):]
                        current_fp = {'name': os_name, 'probes': {}, 'class_info': [], 'cpe': []}
                        continue

                    if not current_fp:
                        continue

                    if line.startswith('Class '):
                        current_fp['class_info'].append(line[len('Class '):])
                        continue

                    if line.startswith('CPE '):
                        current_fp['cpe'].append(line[len('CPE '):])
                        continue

                    match = re.match(r'^([A-Z0-9]+)\((.*)\)$', line)
                    if match:
                        probe_name, probe_data = match.groups()
                        current_fp['probes'][probe_name] = {}
                        attributes = probe_data.split('%')
                        for attr in attributes:
                            if '=' in attr:
                                key, value = attr.split('=', 1)
                                current_fp['probes'][probe_name][key] = value

                if current_fp:  # Append the last one
                    self.fingerprints.append(current_fp)
            logging.info(f"[*] Successfully parsed {len(self.fingerprints)} OS fingerprints from DB.")
        except FileNotFoundError:
            logging.error(f"[-] Nmap OS DB not found at {self.nmap_db_path}")
        except Exception as e:
            logging.error(f"[-] Error parsing Nmap OS DB: {e}")

    def score_target(self, target_results: dict):
        """
        Iterate through all loaded DB fingerprints. Compare the target_results
        to each signature. Use the MATCH_POINTS weights to add up the score.
        This is a simplified scoring engine that only does exact matches.
        """
        best_match = None
        highest_score = 0
        total_points = sum(sum(v.values()) for v in MATCH_POINTS.values())

        logging.info("[*] Scoring collected fingerprint against database...")
        for fp in self.fingerprints:
            current_score = 0
            for probe_name, attributes in target_results.items():
                if probe_name in fp['probes']:
                    db_probe = fp['probes'][probe_name]
                    for attr, value in attributes.items():
                        # This is a major simplification. It only handles exact matches.
                        # A full engine would need to parse ranges (A-F), alternatives (O|S+), etc.
                        if attr in db_probe and value in db_probe[attr].split('|'):
                            current_score += MATCH_POINTS.get(probe_name, {}).get(attr, 0)

            if current_score > highest_score:
                highest_score = current_score
                best_match = fp

        if best_match:
            accuracy = (highest_score / total_points) * 100
            print(f"\n[+] Best Match Found: {best_match['name']}")
            print(f"    Accuracy: {accuracy:.2f}%")
            for c in best_match.get('class_info', []):
                print(f"    Class: {c}")
            for cpe in best_match.get('cpe', []):
                print(f"    CPE: {cpe}")
        else:
            print("[-] No matching OS fingerprint found.")

        return best_match


class Start:
    """
    Module entry point. Orchestrates the OS fingerprinting process.
    """
    def find_closed_tcp(self, target_ip: str):
        """Actively scans for a closed TCP port by looking for an RST response."""
        for _ in range(5):
            port = random.randint(30000, 60000)
            ans = sr1(IP(dst=target_ip)/TCP(dport=port, flags="S"), timeout=0.5, verbose=0)
            if ans and ans.haslayer(TCP) and 'R' in str(ans[TCP].flags):
                return port
        return None

    def find_closed_udp(self, target_ip: str):
        """Actively scans for a closed UDP port by looking for an ICMP Port Unreachable."""
        for _ in range(5):
            port = random.randint(30000, 60000)
            ans = sr1(IP(dst=target_ip)/UDP(dport=port), timeout=0.5, verbose=0)
            if ans and ans.haslayer(ICMP) and ans[ICMP].type == 3 and ans[ICMP].code == 3:
                return port
        return None

    def __init__(self, args=None):
        try:
            with open(path_to_db_config) as f:
                db = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            db = {}

        target_ip = db.get("R_HOST")
        open_port_str = db.get("R_PORT")

        if not target_ip or not open_port_str:
            print("[-] R_HOST and R_PORT must be set in the SuperSploit database.")
            return

        try:
            open_port = int(open_port_str)
        except ValueError:
            print(f"[-] Invalid R_PORT: {open_port_str}. Must be an integer.")
            return

        print(f"[*] Starting OS fingerprinting for {target_ip}")
        print(f"[*] Searching for explicitly closed TCP/UDP ports to ensure accurate T5-T7/U1 probes...")

        closed_tcp = self.find_closed_tcp(target_ip)
        closed_udp = self.find_closed_udp(target_ip)

        if not closed_tcp:
            closed_tcp = open_port + 1 if open_port < 65535 else open_port - 1
            print(f"[-] Could not find a closed TCP port. Falling back to guess: {closed_tcp}")
        else:
            print(f"[+] Found closed TCP port: {closed_tcp}")

        if not closed_udp:
            closed_udp = 31337
            print(f"[-] Could not find a closed UDP port. Falling back to guess: {closed_udp}")
        else:
            print(f"[+] Found closed UDP port: {closed_udp}")

        print(f"[*] Using Open Port: {open_port}, Closed TCP: {closed_tcp}, Closed UDP: {closed_udp}")

        try:
            engine = OSFingerprintEngine(target_ip, open_port, closed_tcp, closed_udp)
            results = engine.run_all_probes()

            print("\n[*] Collected Fingerprint:")
            captured_fingerprint = []
            for probe, data in results.items():
                if data:
                    attrs = '%'.join([f"{k}={v}" for k, v in data.items()])
                    print(f"    {probe}({attrs})")
                    captured_fingerprint.append(f"{probe}({attrs})")

            matcher = NmapDBMatcher(path_to_nmap_db)
            if matcher.fingerprints:
                best_match = matcher.score_target(results)
                if best_match:
                    try:
                        with open(path_to_targets, 'r') as f:
                            targets_db = json.load(f)
                            if not isinstance(targets_db, dict):
                                targets_db = {"TARGETS": {}}
                    except (FileNotFoundError, json.JSONDecodeError):
                        targets_db = {"TARGETS": {}}

                    targets_dict = targets_db.setdefault("TARGETS", {})
                    target_entry = targets_dict.setdefault(target_ip, {})
                    if not isinstance(target_entry, dict):
                        target_entry = targets_dict[target_ip] = {}

                    target_entry["fingerprint"] = "\n".join(captured_fingerprint)
                    target_entry["best match"] = best_match["name"]

                    try:
                        with open(path_to_targets, 'w') as f:
                            json.dump(targets_db, f, indent=4)
                        print("[*] Successfully saved OS fingerprint to targets database.")
                    except Exception as e:
                        print(f"[-] Failed to save to targets database: {e}")

        except PermissionError:
            print("\n[-] PermissionError: This script requires root/administrator privileges to craft raw packets.")
            print("[-] Please run SuperSploit with 'sudo'.")
        except Exception as e:
            print(f"\n[-] An unexpected error occurred: {e}")


if __name__ == "__main__":
    Start()

#!#!#!
root: "true"
name: "Nmap OS Fingerprinting"
catogory: "reconnaissance"
description: "Performs OS fingerprinting using Nmap-style probes and matches against the nmap-os-db."
author: "Donald Ford"
#!#!#!