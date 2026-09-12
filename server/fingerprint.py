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

if __name__ == "__main__":
    print("--- Test 1: pentest tool usage ---")
    sample_cmds = ["whoami", "nmap -sV 127.0.0.1", "cat /etc/shadow"]
    sample_times = [100.0, 100.5, 101.0, 101.5]
    print(score_session(sample_cmds, sample_times))

    print("\n--- Test 2: fast, regular timing (scripted) ---")
    sample_cmds2 = ["whoami", "id", "uname -a", "cat /etc/passwd"]
    sample_times2 = [100.0, 100.2, 100.4, 100.6]
    print(score_session(sample_cmds2, sample_times2))

    print("\n--- Test 3: irregular timing (likely human) ---")
    sample_cmds3 = ["ls", "cd Documents", "cat notes.txt"]
    sample_times3 = [100.0, 102.3, 108.9, 109.1]
    print(score_session(sample_cmds3, sample_times3))

    print("\n--- Test 4: clean, verbose commands (possible llm-agent) ---")
    sample_cmds4 = [
        "find / -name '*.conf' 2>/dev/null | grep -i backup",
        "cat /etc/passwd | grep -v nologin",
        "systemctl status nginx --no-pager"
    ]
    sample_times4 = [100.0, 100.9, 101.8, 102.7]
    print(score_session(sample_cmds4, sample_times4))