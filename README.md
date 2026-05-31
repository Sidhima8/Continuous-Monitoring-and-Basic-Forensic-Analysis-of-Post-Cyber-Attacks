# Continuous-Monitoring-and-Basic-Forensic-Analysis-of-Post-Cyber-Attacks

**1. Introduction**
After a system is compromised, attackers often perform activities such as port scanning, repeated connection attempts, and system-level interactions. Monitoring these activities is important to detect suspicious behavior early.

This project provides a real-time monitoring dashboard that tracks system and network activity, analyzes the collected data, and displays it through a web interface. It also maintains logs, supports basic report generation, and presents events in a timeline format for analysis.

**2. Aim**
To develop a continuous monitoring system with basic forensic analysis that observes target IP activity, maintains logs, and presents data through a dashboard.

**3. Objectives**
To monitor target IP addresses
To perform network scanning
To collect system and scan data
To analyze basic suspicious patterns
To maintain logs of activities
To generate simple reports
To observe events in a timeline format
To visualize data using charts
To generate alerts when required

**4. Theory**
After gaining access to a system, attackers often perform activities that leave observable traces such as:

Open ports and services
Changes in system resource usage
Repeated scanning or connection patterns
Basic forensic analysis in this project is achieved through:

Maintaining logs of system and network activity
Observing the sequence of events over time (timeline)
Generating reports from collected data
This system uses:

Network scanning to identify open ports
System monitoring to observe resource usage
Basic analysis to detect unusual patterns
Logs and timelines for activity tracking
Visualization for easier understanding

**5. How It Works**
User enters a target IP address

The Flask backend starts continuous monitoring

Scanner modules perform:

Port scanning
Host checking
System monitoring
Data is collected and stored as logs

Data is analyzed for suspicious patterns

Alerts are triggered if required

Reports are generated from collected data

Events are tracked in a timeline format

Data is sent to the frontend dashboard

**6. Key Features**
Continuous real-time monitoring
Network scanning using Nmap
System monitoring using psutil
Basic anomaly detection
Log generation and storage
Timeline-based event tracking
Simple report generation
Dashboard visualization using charts
Email alert system

**7. Important Notes**
Nmap must be installed separately
Proper permissions may be required for scanning
Only valid IP addresses should be used
Logs are important for analysis and should be maintained
This project is intended for educational purposes

**8. Result**
The system successfully monitors the target IP and displays system and network data in real time. It maintains logs, generates reports, and presents events in a timeline format, helping in identifying suspicious activity.

**9. Conclusion**
The project demonstrates a monitoring system that combines real-time observation with basic forensic analysis through logs, reports, and timelines. It provides a structured approach to understanding system and network activity after potential access.
