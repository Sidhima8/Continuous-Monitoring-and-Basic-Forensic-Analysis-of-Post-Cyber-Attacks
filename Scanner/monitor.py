import time

from scanner.nmap_scan import run_nmap
from scanner.analyzer import analyze_nmap
from scanner.system_scan import system_info

from report.report import generate_report
from scanner.email_alert import send_email, generate_recommendations

#GLOBAL DATA
previous_results = {}
current_results = {}
alerts = []

targets = []
sent_alerts = set()
threat_targets = set()


#Add target
def add_target(ip):
    if ip and ip not in targets:
        targets.append(ip)
        print(f"[INFO] Added target: {ip}")


#Detection logic
def detect_anomalies(target, old, new, system_stats):
    detected_alerts = []

    if new.get("open_ports", 0) > old.get("open_ports", 0):
        detected_alerts.append("[HIGH] New port opened")

    if new.get("open_ports", 0) > 5:
        detected_alerts.append("[MEDIUM] Too many open ports")

    services = str(new).lower()
    if "ftp" in services or "telnet" in services:
        detected_alerts.append("[HIGH] Suspicious service detected")

    sys_data = str(system_stats).lower()
    if "failed" in sys_data:
        detected_alerts.append("[HIGH] Brute force detected")

    if "root" in sys_data:
        detected_alerts.append("[CRITICAL] Root activity detected")

    return detected_alerts


#MAIN LOOP (LIKE YOUR ORIGINAL WORKING VERSION)
def monitor_loop(delay=5):
    global previous_results, current_results, alerts

    print("[INFO] Real-time monitoring started...")

    while True:
        for target in targets:
            print(f"[SCAN] {target}")

            try:
                network_output = run_nmap(target)
                network_stats = analyze_nmap(network_output)

                host_output = run_nmap(target, arguments="-A")
                system_stats = system_info()

                current_results[target] = {
                    "network": network_stats,
                    "host": host_output,
                    "system": system_stats
                }

                old = previous_results.get(target, {})
                detected = detect_anomalies(target, old, network_stats, system_stats)

                report_path = None

                #Generate report only if threat
                if detected:
                    recommendations = generate_recommendations(network_stats)

                    report_path = generate_report(
                        network_stats,
                        system_stats,
                        host_output,
                        recommendations
                    )

                    print(f"[ALERT] Report generated: {report_path}")

                #Alerts (FIXED PROPERLY)
                for alert_msg in detected:
                    alert_key = f"{target}_{alert_msg}"

                    if alert_key not in sent_alerts:
                        from datetime import datetime

                        timestamp = datetime.now().strftime("%H:%M:%S")
                        log_entry = f"[{timestamp}] {alert_msg}"

                        print(f"{log_entry} on {target}")

                        alerts.append(log_entry)
                        threat_targets.add(target)

                        #Save logs
                        try:
                            with open("attack_logs.txt", "a") as f:
                                f.write(f"{target} {log_entry}\n")
                        except:
                            pass

                        #Send email
                        if report_path:
                            send_email(report_path, network_stats)

                        sent_alerts.add(alert_key)

                previous_results[target] = network_stats

            except Exception as e:
                print(f"[ERROR] {e}")

        time.sleep(delay)