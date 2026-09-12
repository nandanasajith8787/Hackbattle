import statistics

KNOWN_TOOL_PATTERNS = ["nmap", "hydra", "sqlmap", "metasploit", "nikto", "gobuster", "wget", "curl"]

# Common typo/correction indicators that suggest a real human typing
HUMAN_INDICATORS = ["\x7f", "\x08"]  # backspace/delete chars, if your SSH layer captures them

def score_session(commands: list, timestamps: list) -> dict:
    risk_score = 0
    flags = []
    tool_hit = False

    for cmd in commands:
        cmd_lower = cmd.lower()
        for tool in KNOWN_TOOL_PATTERNS:
            if tool in cmd_lower:
                risk_score += 25
                flags.append(f"Automated Tool Detected: {tool}")
                tool_hit = True

        if "credentials" in cmd_lower or "shadow" in cmd_lower or "id_rsa" in cmd_lower:
            risk_score += 30
            flags.append("Credential Discovery Attempt")

        if "sudo" in cmd_lower or "chmod" in cmd_lower:
            risk_score += 15
            flags.append("Privilege Escalation Attempt")

    # --- Timing analysis ---
    avg_interval = None
    stddev_interval = None
    if len(timestamps) > 3:
        intervals = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]
        avg_interval = sum(intervals) / len(intervals)
        stddev_interval = statistics.pstdev(intervals)

        if avg_interval < 1.0:
            risk_score += 20
            flags.append("High-Speed Automated Execution")

        # Very consistent gaps = strong script/bot signal, even if not fast
        if stddev_interval < 0.15:
            risk_score += 20
            flags.append("Unnaturally Regular Timing (low variance)")

    # --- LLM-agent heuristic ---
    # Looks for unusually clean, verbose, well-formed commands with no typos/corrections,
    # often chained correctly with flags, and no backspace/delete characters at all.
    avg_cmd_length = sum(len(c) for c in commands) / len(commands) if commands else 0
    has_correction_chars = any(
        any(ind in cmd for ind in HUMAN_INDICATORS) for cmd in commands
    )
    well_formed_count = sum(
        1 for c in commands if len(c.split()) > 2 and ("--" in c or "|" in c or "&&" in c)
    )
    llm_agent_signal = (
        not has_correction_chars
        and avg_cmd_length > 25
        and well_formed_count >= max(1, len(commands) // 3)
    )
    if llm_agent_signal:
        flags.append("Unusually Clean/Verbose Command Structure (possible LLM agent)")

    risk_score = min(risk_score, 100)

    # --- Final classification into required categories ---
    if tool_hit:
        session_type = "pentest-tool"
    elif llm_agent_signal:
        session_type = "llm-agent"
    elif stddev_interval is not None and stddev_interval < 0.15:
        session_type = "scripted"
    elif has_correction_chars or (stddev_interval is not None and stddev_interval > 0.5):
        session_type = "human"
    else:
        session_type = "human" if risk_score < 35 else "scripted"

    return {
        "session_type": session_type,
        "risk_score": risk_score,
        "flags": flags,
        "avg_interval": avg_interval,
        "stddev_interval": stddev_interval,
    }