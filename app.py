from flask import Flask, render_template, request, jsonify, send_from_directory
import threading

from scanner.monitor import monitor_loop, current_results, alerts, add_target, threat_targets

app = Flask(__name__)

# 🏠 Dashboard
@app.route("/")
def index():
    return render_template("index.html")


# 🎯 Add Target
@app.route("/add_target", methods=["POST"])
def add_target_api():
    ip = request.form.get("ip")
    if ip:
        add_target(ip)
        print(f"[INFO] Target added: {ip}")
    return "OK"


# 📊 Send Data
@app.route("/api/data")
def get_data():
    threats = len(alerts)

    # 🔥 Convert to percentage properly
    risk = min(threats * 15, 100)
    safe = 100 - risk

    return jsonify({
        "alerts": alerts,
        "stats": {
            "threats": threats,
            "safe": safe,
            "risk": risk
        }
    })

# ✅ 🔥 Serve reports from reports/ folder
@app.route("/reports/<path:filename>")
def serve_report(filename):
    return send_from_directory("reports", filename)


# ✅ 🔥 Generate report
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


# 🔁 Background Monitoring
def run_monitor():
    print("[INFO] Monitoring started...")
    monitor_loop()


if __name__ == "__main__":
    t = threading.Thread(target=run_monitor)
    t.daemon = True
    t.start()

    app.run(host="0.0.0.0", port=5000, debug=True)