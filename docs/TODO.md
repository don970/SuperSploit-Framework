# Remaining Weaknesses (The Noisy Aspects)
### TODO: Cleartext Payload Delivery: The Python code for Stage 2 is sent over the network (and loaded into memory) in plain text. Even if the network layer is encrypted with TLS, if the target environment is hooking Python's exec() or eval() functions, the raw script will be dumped and easily analyzed by AV.
### TODO: The shell=True Fallback: While basic commands are silent, any command you type that isn't explicitly handled (e.g., whoami, netstat, or executing a binary) will fall back to subprocess.run(..., shell=True). This will immediately spawn a noisy shell process.
### TODO: Lack of Obfuscation: The code variables (run_c2, client_socket, cmd) are highly recognizable to heuristic scanners.

# How to Achieve "High/Advanced" Stealth:
***To make this payload truly advanced, you would need to***:
### TODO: ***Obfuscate Imports***: Encode the Payload: Base64 or XOR encode the Stage 2 payload on the server before sending it, and have the Stage 1 stager decode it in memory just before execution. This hides the cleartext Python script from basic memory scanners. Use dynamic imports (like getattr(__import__('os'), 'system')) to hide the fact that the script is importing modules like subprocess or os.
### TODO: ***Expand Native Capabilities***: Add native Python implementations for downloading/uploading files (using socket reading/writing) and process enumeration to further reduce reliance on the subprocess fallback.
