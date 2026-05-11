from typing import List, Dict, Any

class AutoSuggestCommand:
    def __init__(self, exploit_cache):
        """
        Initializes the auto_suggest command.
        Expects exploit_cache to have an 'all_exploits' attribute containing your exploit modules.
        """
        self.exploit_cache = exploit_cache

    def execute(self, target_ip: str, target_open_ports: List[Dict[str, Any]]):
        """
        Reads the target's open ports from RAM and correlates them with available exploits.
        
        :param target_ip: The IP address of the current target.
        :param target_open_ports: A list of dicts, e.g., [{'port': 8080, 'service': 'http'}]
        """
        print(f"[*] Analyzing target {target_ip} for exploit correlation...")
        
        if not target_open_ports:
            print("[-] No open ports found in RAM. Please run an Nmap scan first.")
            return

        suggestions = []
        
        for port_info in target_open_ports:
            port_num = str(port_info.get('port', ''))
            service_name = str(port_info.get('service', '')).lower()
            
            for exploit in self.exploit_cache.all_exploits:
                # Extract keywords from the exploit module, falling back to an empty list
                keywords = [str(k).lower() for k in getattr(exploit, 'keywords', [])]
                exploit_name = getattr(exploit, 'name', 'Unknown Exploit')
                
                # Check if the scanned port or service matches any of the exploit's keywords
                if port_num in keywords or service_name in keywords:
                    suggestions.append({
                        'exploit': exploit_name,
                        'port': port_num,
                        'service': service_name,
                        'reason': f"Matched keyword '{port_num}' or '{service_name}'"
                    })
        
        self._display_results(target_ip, suggestions)

    def _display_results(self, target_ip: str, suggestions: List[Dict[str, str]]):
        if not suggestions:
            print(f"[-] No matching exploits found for {target_ip} based on current port data.")
            return
            
        print(f"[+] Found {len(suggestions)} suggested exploit(s) for {target_ip}:")
        for idx, sug in enumerate(suggestions, 1):
            print(f"    {idx}. {sug['exploit']} (Port: {sug['port']}, Service: {sug['service']}) - {sug['reason']}")