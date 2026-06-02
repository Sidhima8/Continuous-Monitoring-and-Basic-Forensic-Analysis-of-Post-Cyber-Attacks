import platform
import psutil
import os


def read_attack_logs():
    logs = ""

    try:
        if os.path.exists("attack_logs.txt"):

            with open("attack_logs.txt", "r") as f:
                lines = f.readlines()[-20:]

            logs += "\n".join(lines)

    except Exception as e:
        logs += f"\n[ERROR] attack_logs.txt: {e}"

    return logs


def read_web_logs():
    logs = ""

    possible_logs = [
        "xampp/apache/logs/access.log",
        "xampp/apache/logs/error.log",
        "/var/log/apache2/access.log",
        "/var/log/apache2/error.log"
    ]

    for path in possible_logs:

        try:
            if os.path.exists(path):

                with open(path, "r", errors="ignore") as f:
                    lines = f.readlines()[-30:]

                logs += "\n".join(lines)

        except:
            pass

    return logs


def detect_web_attacks(web_logs):
    findings = []

    patterns = [
        "union select",
        "' or 1=1",
        "sqlmap",
        "<script>",
        "../",
        "nikto",
        "cmd=",
        "wget",
        "curl"
    ]

    logs = web_logs.lower()

    for pattern in patterns:
        if pattern in logs:
            findings.append(f"[CRITICAL] Web attack detected: {pattern}")

    return findings


def detect_system_attacks():
    findings = []

    try:

        auth_logs = ""

        possible_auth_logs = [
            "/var/log/auth.log",
            "/var/log/secure"
        ]

        for path in possible_auth_logs:

            if os.path.exists(path):

                with open(path, "r", errors="ignore") as f:
                    auth_logs += f.read().lower()

        if "failed password" in auth_logs:
            findings.append("[HIGH] Hydra brute force detected")

        if "authentication failure" in auth_logs:
            findings.append("[HIGH] Authentication failure detected")

    except:
        pass

    return findings


def system_info():

    info = ""

    info += f"System: {platform.system()}\n"
    info += f"Node Name: {platform.node()}\n"
    info += f"Release: {platform.release()}\n"
    info += f"Processor: {platform.processor()}\n\n"

    info += f"CPU Usage: {psutil.cpu_percent()}%\n"
    info += f"Memory Usage: {psutil.virtual_memory().percent}%\n\n"

    web_logs = read_web_logs()

    web_findings = detect_web_attacks(web_logs)

    system_findings = detect_system_attacks()

    attack_logs = read_attack_logs()

    if web_findings:
        info += "\n=== WEB ATTACKS ===\n"
        info += "\n".join(web_findings)

    if system_findings:
        info += "\n=== SYSTEM ATTACKS ===\n"
        info += "\n".join(system_findings)

    if attack_logs:
        info += "\n=== TIMELINE LOGS ===\n"
        info += attack_logs

    return info
