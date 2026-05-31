def analyze_nmap(scan_data):
    open_ports = 0
    services = []
    suspicious_services = []

    #Define risky services (IOC idea)
    risky = ["ftp", "telnet", "rlogin"]

    for host in scan_data:
        protocols = scan_data[host].get("protocols", {})

        for proto in protocols:
            for port_info in protocols[proto]:

                if port_info["state"] == "open":
                    open_ports += 1

                    service = port_info.get("service", "")
                    services.append(service)

                    #Detect suspicious services
                    if service.lower() in risky:
                        suspicious_services.append(service)

    total_checked = 50
    safe_ports = total_checked - open_ports

    return {
        "open_ports": open_ports,
        "safe_ports": safe_ports,
        "services": services,
        "suspicious_services": suspicious_services
    }
