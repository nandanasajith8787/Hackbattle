KNOWN_TOOL_PATTERNS = ["nmap", "hydra", "sqlmap", "metasploit", "nikto", "gobuster", "wget", "curl"]

def score_session(commands: list, timestamps: list) -> dict:
    risk_score = 0
    flags = []
    
    for cmd in commands:
        cmd_lower = cmd.lower()
        for tool in KNOWN_TOOL_PATTERNS:
            if tool in cmd_lower:
                risk_score += 25
                flags.append(f"Automated Tool Detected: {tool}")
        
        if "credentials" in cmd_lower or "shadow" in cmd_lower or "id_rsa" in cmd_lower:
            risk_score += 30
            flags.append("Credential Discovery Attempt")
            
        if "sudo" in cmd_lower or "chmod" in cmd_lower:
            risk_score += 15
            flags.append("Privilege Escalation Attempt")

    if len(timestamps) > 3:
        intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
        avg_interval = sum(intervals) / len(intervals)
        if avg_interval < 1.0:
            risk_score += 20
            flags.append("High-Speed Automated Execution")

    risk_score = min(risk_score, 100)
    
    if risk_score > 70:
        threat_level = "HIGH"
        attacker_type = "Scripted / Automated Scanner"
    elif risk_score > 35:
        threat_level = "MEDIUM"
        attacker_type = "Manual Probe / Targeted"
    else:
        threat_level = "LOW"
        attacker_type = "Reconnaissance"
        
    return {
        "risk_score": risk_score,
        "threat_level": threat_level,
        "attacker_type": attacker_type,
        "flags": flags
    }

if __name__ == "__main__":
    sample_cmds = ["whoami", "nmap -sV 127.0.0.1", "cat /etc/shadow"]
    sample_times = [100.0, 100.5, 101.0]
    print("--- Testing Fingerprint Scorer ---")
    print(score_session(sample_cmds, sample_times))