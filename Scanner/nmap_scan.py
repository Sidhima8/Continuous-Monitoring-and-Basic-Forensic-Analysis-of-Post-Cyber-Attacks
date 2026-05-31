import nmap

def run_nmap(target, arguments=""):
    scanner = nmap.PortScanner()

    try:
        print(f"[INFO] Running Nmap on {target} with args: {arguments}")

        # Run scan
        scanner.scan(target, arguments=arguments)

        results = {}

        for host in scanner.all_hosts():
            results[host] = {
                "state": scanner[host].state(),
                "protocols": {}
            }

            for proto in scanner[host].all_protocols():
                ports = scanner[host][proto].keys()

                results[host]["protocols"][proto] = []

                for port in ports:
                    port_data = scanner[host][proto][port]

                    results[host]["protocols"][proto].append({
                        "port": port,
                        "state": port_data["state"],
                        "service": port_data.get("name", ""),
                    })

        return results

    except Exception as e:
        print(f"[ERROR] Nmap scan failed: {e}")
        return {}