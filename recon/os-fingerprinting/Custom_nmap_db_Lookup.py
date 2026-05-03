"""
Native OS Fingerprinting Engine
Uses Scapy to craft Nmap-style TCP probes (T1, T2, T5) and parses
the target's IP/TCP stack responses into Nmap-compatible signature strings.
"""

import json
import os
import re
import sys
from urllib.parse import urlparse

import re
import os
# Suppress Scapy IPv6 warnings for a cleaner console
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, TCP, sr1, conf

install_location = f'{os.getenv("HOME")}/.SuperSploit'
path_to_database = f"{install_location}/.data/.config/data.json"
nmapdb = f"{install_location}/.data/.config/nmap-os-db.txt"

try:
    with open(path_to_database) as f:
        db = json.load(f)
except FileNotFoundError:
    db = {}


class NmapDBMatcher:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.signatures = []
        self._load_database()

    def _load_database(self):
        """Parses the nmap-os-db.txt file into a list of searchable dictionaries."""
        if not os.path.exists(self.db_path):
            print(f"[-] Error: Nmap database not found at {self.db_path}")
            return

        print("[*] Loading and parsing Nmap OS Database...")
        current_os = None

        with open(self.db_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith("#"):
                    continue

                # Start of a new OS signature block
                if line.startswith("Fingerprint "):
                    if current_os:
                        self.signatures.append(current_os)
                    current_os = {
                        "name": line.split("Fingerprint ", 1)[1],
                        "probes": {}
                    }

                # Parse the probe lines (T1, T2, T5, etc.)
                elif current_os and re.match(r'^(T1|T2|T3|T4|T5|T6|T7|WIN|OPS|SEQ)\(', line):
                    probe_type = line.split('(')[0]
                    # Extract the contents inside the parentheses
                    inner_data = line[len(probe_type) + 1:-1]
                    probe_dict = {}

                    # Split by % and then by = to get key-value pairs
                    for part in inner_data.split('%'):
                        if '=' in part:
                            k, v = part.split('=', 1)
                            probe_dict[k] = v

                    current_os["probes"][probe_type] = probe_dict

        # Append the final block
        if current_os:
            self.signatures.append(current_os)

        print(f"[+] Successfully loaded {len(self.signatures)} OS signatures.")

    def _evaluate_value(self, my_val: str, db_val: str) -> bool:
        """
        Evaluates a single captured value against Nmap's syntax rules.
        Handles exact matches, OR (|) operators, and simple Hex ranges (-).
        """
        if my_val == db_val:
            return True

        # Handle OR operators (e.g., W=1000|2000)
        if '|' in db_val:
            if my_val in db_val.split('|'):
                return True

        # Handle simple ranges (e.g., T=3B-45)
        if '-' in db_val and all(c in "0123456789ABCDEF-" for c in db_val):
            try:
                low, high = db_val.split('-', 1)
                # Convert both my_val and the range boundaries from Hex to Int
                if int(low, 16) <= int(my_val, 16) <= int(high, 16):
                    return True
            except ValueError:
                pass

        return False

    def _parse_my_signature(self, sig_string: str) -> dict:
        """Converts our generated T1(R=Y%DF=Y...) string back into a dict for comparison."""
        result = {}
        if "(" in sig_string and sig_string.endswith(")"):
            inner = sig_string.split("(", 1)[1][:-1]
            for part in inner.split('%'):
                if '=' in part:
                    k, v = part.split('=', 1)
                    result[k] = v
        return result

    def match(self, captured_fingerprints: dict, top_n: int = 3):
        """
        Compares the captured SuperSploit fingerprints against the parsed database.
        Returns the top N matches based on a confidence score.
        """
        print("[*] Correlating captured signatures against database...")
        matches = []

        # Convert our captured strings into dictionaries
        my_probes = {
            probe: self._parse_my_signature(sig)
            for probe, sig in captured_fingerprints.items()
        }

        for db_os in self.signatures:
            score = 0
            max_possible_score = 0

            for probe_type, my_data in my_probes.items():
                if probe_type in db_os["probes"]:
                    db_data = db_os["probes"][probe_type]

                    # Compare each key (R, DF, W, O, etc.)
                    for key, my_val in my_data.items():
                        if key in db_data:
                            # Weight the TCP Options (O) and Window (W) heavily
                            weight = 3 if key in ['O', 'W'] else 1
                            max_possible_score += weight

                            if self._evaluate_value(my_val, db_data[key]):
                                score += weight

            # Calculate confidence percentage
            if max_possible_score > 0:
                confidence = (score / max_possible_score) * 100
                if confidence > 50:  # Only log reasonable matches
                    matches.append((confidence, db_os["name"]))

        # Sort matches by highest confidence descending
        matches.sort(key=lambda x: x[0], reverse=True)

        return matches[:top_n]


class OSFingerprintEngine:
    def __init__(self, target_ip: str, open_port: int, closed_port: int = 31337):
        self.target = target_ip
        self.open_port = open_port
        self.closed_port = closed_port
        self.fingerprint = {}

    def parse_nmap_options(self, tcp_layer):
        """Translates Scapy's TCP options list into Nmap's 'O' string format."""
        if not tcp_layer.options:
            return ""

        nmap_opt_string = ""
        for opt in tcp_layer.options:
            name = opt[0]
            val = opt[1] if len(opt) > 1 else None

            if name == 'MSS':
                nmap_opt_string += f"M{val:X}"
            elif name == 'WScale':
                nmap_opt_string += f"W{val}"
            elif name == 'NOP':
                nmap_opt_string += "N"
            elif name == 'SAckOK':
                nmap_opt_string += "S"
            elif name == 'Timestamp':
                ts_val, ts_ecr = val
                v1 = "1" if ts_val != 0 else "0"
                v2 = "1" if ts_ecr != 0 else "0"
                nmap_opt_string += f"T{v1}{v2}"

        return nmap_opt_string

    def get_base_ttl(self, ttl):
        """Guesses the initial TTL based on the received TTL."""
        if ttl <= 64:
            return 64
        elif ttl <= 128:
            return 128
        else:
            return 255

    def format_probe_result(self, response, probe_id):
        """Extracts Nmap-relevant fields from a Scapy response."""
        if response is None:
            return f"{probe_id}(R=N)"

        ip_layer = response.getlayer(IP)
        tcp_layer = response.getlayer(TCP)

        if not ip_layer or not tcp_layer:
            return f"{probe_id}(R=N)"

        df = "Y" if "DF" in ip_layer.flags else "N"
        w = tcp_layer.window
        t = ip_layer.ttl
        tg = self.get_base_ttl(t)
        o = self.parse_nmap_options(tcp_layer)

        return f"{probe_id}(R=Y%DF={df}%T={t}%TG={tg}%W={w:X}%O={o})"

    def execute_probes(self):
        """Sends the T1, T2, and T5 probes and records the signatures."""
        print(f"[*] Commencing Nmap-style probes against {self.target}")

        # T1: Standard SYN to Open Port
        pkt_t1 = IP(dst=self.target) / TCP(
            dport=self.open_port, flags="S", window=32768,
            options=[('WScale', 10), ('NOP', None), ('MSS', 1460), ('Timestamp', (0xFFFFFFFF, 0)), ('SAckOK', '')]
        )
        resp_t1 = sr1(pkt_t1, timeout=2, verbose=0)
        self.fingerprint['T1'] = self.format_probe_result(resp_t1, "T1")

        # T2: NULL to Open Port
        pkt_t2 = IP(dst=self.target, flags="DF") / TCP(
            dport=self.open_port, flags="", window=128
        )
        resp_t2 = sr1(pkt_t2, timeout=2, verbose=0)
        self.fingerprint['T2'] = self.format_probe_result(resp_t2, "T2")

        # T5: SYN to Closed Port
        pkt_t5 = IP(dst=self.target) / TCP(
            dport=self.closed_port, flags="S", window=31337
        )
        resp_t5 = sr1(pkt_t5, timeout=2, verbose=0)
        self.fingerprint['T5'] = self.format_probe_result(resp_t5, "T5")

    def display_results(self):
        print("\n[+] Fingerprint Capture Complete")
        print("-" * 50)
        print("Generated Nmap Signatures:")
        for key, value in self.fingerprint.items():
            print(f"  {value}")
        print("-" * 50)
        print("[*] Ready for fuzzy comparison against nmap-os-db.txt")
        return self.fingerprint


class Start:
    def __init__(self, args=None):
        # 1. Require root privileges for Scapy raw sockets
        if os.geteuid() != 0:
            print("[-] Error: OS Fingerprinting requires root privileges.")
            print("[*] Please run SuperSploit with sudo.")
            return

        # 2. Parse target IP
        raw_target = str(db.get("R_HOST", ""))
        if "://" in raw_target:
            target_ip = urlparse(raw_target).hostname
        else:
            target_ip = raw_target.split(":")[0]

        if not target_ip:
            print("[-] No valid R_HOST set in the database.")
            return

        # 3. Pull an open port from the DB, default to 80 if not found
        open_port = int(db.get("R_PORT", 80))

        # Initialize and run
        engine = OSFingerprintEngine(target_ip, open_port)
        engine.execute_probes()
        data = engine.display_results()
        matcher = NmapDBMatcher(nmapdb)
        matches = matcher.match(data)
        print("-" * 50)
        for percent, match in enumerate(matches):
            print(F"{percent}: {match}")
        print("-" * 50)
        return



#!#!#!
name: "OS Fingerprinter (Native)"
category: "Recon"
desc: """Crafts specialized Nmap-style TCP probes (T1, T2, T5) using Scapy to analyze 
IP/TCP stack nuances. Generates signatures compatible with the Nmap OS database."""
author: "Donald Ford"
#!#!#!