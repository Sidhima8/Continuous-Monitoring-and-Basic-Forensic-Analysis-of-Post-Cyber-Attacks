import time
from scanner.nmap_scan import run_nmap
from scanner.analyzer import analyze_nmap
from scanner.system_scan import system_info

# Store results
previous_results = {}
current_results = {}
alerts = []

# Add multiple targets here
targets = ["127.0.0.1"]

def monitor_loop():
    global previous_results, current_results, alerts

    while True:
        for target in targets:

            #NETWORK + HOST SCAN
            output = run_nmap(target)
            stats = analyze_nmap(output)

            #SYSTEM SCAN
            system = system_info()

            # Store current state
            current_results[target] = {
                "stats": stats,
                "system": system
            }

            # First scan
            if target not in previous_results:
                previous_results[target] = stats
            else:
                old = previous_results[target]

                #Detection Rules

                # New port opened
                if stats["open_ports"] > old["open_ports"]:
                    alerts.append(f"[HIGH] New port opened on {target}")

                # Too many open ports
                if stats["open_ports"] > 5:
                    alerts.append(f"[MEDIUM] Too many open ports on {target}")

            previous_results[target] = stats

        time.sleep(20)  # runs every 20 sec