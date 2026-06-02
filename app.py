from flask import Flask, render_template, request, jsonify, send_from_directory
import threading

from scanner.monitor import (
    monitor_loop,
    current_results,
    alerts,
    add_target,
    threat_targets,
    scan_target
)

app = Flask(__name__)

# Dashboard
@app.route("/")
def index():
    return render_template("index.html")

# Add Target
@app.route("/add_target", methods=["POST"])
def add_target_api():

    ip = request.form.get("ip")

    if ip:

        add_target(ip)
        print(f"[INFO] Target added: {ip}")

        # Immediate scan
        scan_target(ip)

    return "OK"


# Send Dynamic Data
@app.route("/api/data")
def get_data():

    total_targets = len(current_results)

    total_risk = 0
    critical = 0
    high = 0
    medium = 0
    low = 0

    for alert in alerts:

        if "CRITICAL" in alert:
            total_risk += 40
            critical += 1

        elif "HIGH" in alert:
            total_risk += 25
            high += 1

        elif "MEDIUM" in alert:
            total_risk += 15
            medium += 1

        else:
            total_risk += 5
            low += 1

    # Dynamic Risk
    risk = min(total_risk, 100)

    safe = max(0, 100 - risk)

    return jsonify({
        "alerts": alerts[-20:],

        "timeline": alerts[-10:],

        "stats": {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,

            "risk": risk,
            "safe": safe,

            "total_alerts": len(alerts),

            "targets": total_targets
        }
    })

# Serve reports from reports/ folder
@app.route("/reports/<path:filename>")
def serve_report(filename):
    return send_from_directory("reports", filename)


# Generate report
@app.route("/generate_report", methods=["POST"])
def manual_report():
    from report.report import generate_report

    if not current_results:
        return jsonify({"status": "no_data"})

    target = list(current_results.keys())[-1]
    data = current_results[target]

    generate_report(
        data.get("network", {}),
        data.get("system", ""),
        data.get("host", ""),
        "Manual report generated"
    )

    print("[REPORT] Generated successfully")

    return jsonify({"status": "success"})


# Background Monitoring
def run_monitor():
    print("[INFO] Monitoring started...")
    monitor_loop()


if __name__ == "__main__":
    t = threading.Thread(target=run_monitor)
    t.daemon = True
    t.start()

    app.run(host="0.0.0.0", port=5000, debug=True)
