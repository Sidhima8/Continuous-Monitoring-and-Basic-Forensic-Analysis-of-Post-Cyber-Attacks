import time
from datetime import datetime

from scanner.nmap_scan import run_nmap
from scanner.analyzer import analyze_nmap
from scanner.system_scan import system_info

from report.report import generate_report
from scanner.email_alert import send_email, generate_recommendations


previous_results = {}
current_results = {}
alerts = []

targets = []

sent_alerts = set()

threat_targets = set()

timeline_logs = []


def save_attack_log(message):

    with open("attack_logs.txt", "a") as f:
        f.write(message + "\n")


def add_target(ip):
    if ip and ip not in targets:
        targets.append(ip)
        print(f"[INFO] Added target: {ip}")


def detect_anomalies(target, old, new, system_stats):

    detected_alerts = []

    stats = str(system_stats).lower()

    # SQL Injection
    sql_patterns = [
        "union select",
        "' or 1=1",
        "sqlmap",
        "information_schema",
        "sleep(",
        "benchmark("
    ]

    for pattern in sql_patterns:
        if pattern in stats:
            detected_alerts.append(
                f"[CRITICAL] SQL Injection detected ({pattern})"
            )

    # XSS
    xss_patterns = [
        "<script>",
        "onerror=",
        "alert(",
        "svg onload"
    ]

    for pattern in xss_patterns:
        if pattern in stats:
            detected_alerts.append(
                f"[HIGH] XSS payload detected ({pattern})"
            )

    # Nikto
    nikto_patterns = [
        "nikto",
        "robots.txt",
        ".git",
        "phpinfo",
        "cgi-bin"
    ]

    for pattern in nikto_patterns:
        if pattern in stats:
            detected_alerts.append(
                f"[MEDIUM] Web scan detected ({pattern})"
            )

    # Hydra
    hydra_patterns = [
        "hydra",
        "failed password",
        "authentication failure",
        "login failed"
    ]

    failed_count = 0

    for pattern in hydra_patterns:
        if pattern in stats:
            failed_count += 1

    if failed_count >= 2:
        detected_alerts.append(
            "[HIGH] Hydra brute force detected"
        )

    # Nmap
    if new["open_ports"] > old.get("open_ports", 0):
        detected_alerts.append(
            "[MEDIUM] Port scanning activity detected"
        )

    # Excessive Ports
    if new["open_ports"] > 10:
        detected_alerts.append(
            "[HIGH] Suspicious number of open ports"
        )

    # Suspicious Services
    services = str(new).lower()

    suspicious_services = [
        "ftp",
        "telnet",
        "smb",
        "netbios",
        "rlogin"
    ]

    for service in suspicious_services:
        if service in services:
            detected_alerts.append(
                f"[HIGH] Suspicious service detected ({service})"
            )

    # Directory Traversal
    traversal_patterns = [
        "../",
        "..\\",
        "/etc/passwd",
        "boot.ini"
    ]

    for pattern in traversal_patterns:
        if pattern in stats:
            detected_alerts.append(
                f"[CRITICAL] Directory traversal detected ({pattern})"
            )

    return list(set(detected_alerts))

def scan_target(target):

    try:

        print(f"[SCAN] Immediate scan started on {target}")

        # Network Scan
        network_output = run_nmap(target)

        network_stats = analyze_nmap(network_output)

        # Host Scan
        host_output = run_nmap(target, arguments="-A")

        # System Scan
        system_stats = system_info()

        # Store Results
        current_results[target] = {
            "network": network_stats,
            "host": host_output,
            "system": system_stats
        }

        old = previous_results.get(target, {})

        detected = detect_anomalies(
            target,
            old,
            network_stats,
            system_stats
        )

        recommendations = generate_recommendations(network_stats)

        # Generate Report
        report_path = generate_report(
            network_stats,
            system_stats,
            host_output,
            recommendations
        )

        # Alerts
        for alert_msg in detected:

            alert_key = f"{target}_{alert_msg}"

            if alert_key not in sent_alerts:

                alerts.append(f"{alert_msg} on {target}")

                threat_targets.add(target)

                send_email(report_path, network_stats)

                sent_alerts.add(alert_key)

        previous_results[target] = network_stats

        print(f"[SUCCESS] Scan complete: {target}")

    except Exception as e:
        print(f"[ERROR] {e}")

def monitor_loop(cycles=999999, delay=5):

    global previous_results, current_results, alerts

    print("[INFO] Monitoring started...")

    while True:

        for target in targets:

            scan_target(target)

        time.sleep(delay)
