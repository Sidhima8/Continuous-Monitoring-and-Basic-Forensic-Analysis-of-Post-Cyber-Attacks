let lineChart, doughnutChart, gaugeChart;

//Start Monitoring
function startMonitoring() {
    let ip = document.getElementById("ip").value;

    if (!ip) {
        alert("Enter IP");
        return;
    }

    fetch("/add_target", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: "ip=" + ip
    });

    document.getElementById("liveBadge").style.display = "block";
}

// ⚙️ Generate Report
function generateReport() {
    let status = document.getElementById("reportStatus");

    status.innerText = "Generating report...";

    fetch("/generate_report", {
        method: "POST"
    })
    .then(res => res.json())
    .then(data => {
        if (data.status === "success") {
            status.innerText = "Report generated";
            loadReport();
        } else {
            status.innerText = "No data available";
        }
    })
    .catch(() => {
        status.innerText = "Error generating report";
    });
}

//View Report
function loadReport() {
    document.getElementById("pdfFrame").src =
        "/reports/security_report_latest.pdf?time=" + new Date().getTime();
}

//Download Report
function downloadReport() {
    const link = document.createElement("a");
    link.href = "/reports/security_report_latest.pdf";
    link.download = "security_report.pdf";
    link.click();
}


//REAL-TIME UPDATE
setInterval(() => {

    fetch("/api/data")
    .then(res => res.json())
    .then(data => {

        let risk = data.stats.risk;

        //CARDS
        document.getElementById("alertsCount").innerText = data.alerts.length;
        document.getElementById("riskLevel").innerText = risk + "%";

        //LINE CHART
        let values = data.alerts.map((_, i) => i + 1).slice(-20);

        if (!lineChart) {
            lineChart = new Chart(document.getElementById("chart"), {
                type: "line",
                data: {
                    labels: values,
                    datasets: [{
                        label: "Threat Activity",
                        data: values,
                        borderColor: "#a855f7"
                    }]
                }
            });
        } else {
            lineChart.data.labels = values;
            lineChart.data.datasets[0].data = values;
            lineChart.update();
        }

        //DOUGHNUT (FIXED %)
        let threatPercent = data.stats.risk;
        let safePercent = 100 - threatPercent;

        if (!doughnutChart) {
            doughnutChart = new Chart(document.getElementById("doughnutChart"), {
                type: "doughnut",
                data: {
                    labels: ["Threat %", "Safe %"],
                    datasets: [{
                        data: [threatPercent, safePercent],
                        backgroundColor: ["#ef4444", "#22c55e"]
                    }]
                }
            });
        } else {
            doughnutChart.data.datasets[0].data = [threatPercent, safePercent];
            doughnutChart.update();
        }

        //GAUGE
        let color = risk < 30 ? "#22c55e" : risk < 70 ? "#f59e0b" : "#ef4444";

        if (!gaugeChart) {
            gaugeChart = new Chart(document.getElementById("gauge"), {
                type: "doughnut",
                data: {
                    datasets: [{
                        data: [risk, 100 - risk],
                        backgroundColor: [color, "#1e293b"],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: false,
                    circumference: 180,
                    rotation: 270,
                    cutout: "80%",
                    plugins: { legend: { display: false } }
                }
            });
        } else {
            gaugeChart.data.datasets[0].data = [risk, 100 - risk];
            gaugeChart.data.datasets[0].backgroundColor = [color, "#1e293b"];
            gaugeChart.update();
        }

        //ALERTS (with colors)
        let alertBox = document.getElementById("alertList");
        alertBox.innerHTML = "";

        data.alerts.slice(-5).forEach(a => {
            let div = document.createElement("div");
            div.className = "alert-row";

            if (a.includes("CRITICAL")) div.style.color = "#ef4444";
            else if (a.includes("HIGH")) div.style.color = "#f97316";
            else if (a.includes("MEDIUM")) div.style.color = "#eab308";
            else div.style.color = "#22c55e";

            div.innerText = a;
            alertBox.appendChild(div);
        });

    })
    .catch(err => console.log("API error:", err));

}, 1000);
