import psutil
import datetime

def host_scan():
    result = ""

    #Basic System Info
    result += "===== HOST INFORMATION =====\n"
    result += f"Time: {datetime.datetime.now()}\n\n"

    #CPU + Memory
    result += f"CPU Usage: {psutil.cpu_percent()}%\n"
    result += f"Memory Usage: {psutil.virtual_memory().percent}%\n\n"

    #Running Processes
    result += "===== RUNNING PROCESSES =====\n"
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            result += f"PID: {proc.info['pid']} | Name: {proc.info['name']}\n"
        except:
            pass

    #Logged-in Users
    result += "\n===== LOGGED-IN USERS =====\n"
    for user in psutil.users():
        result += f"User: {user.name}\n"

    #Open Ports (Local)
    result += "\n===== OPEN PORTS =====\n"
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'LISTEN':
            result += f"Port: {conn.laddr.port}\n"

    #Simple Suspicious Detection
    result += "\n===== ALERT CHECK =====\n"
    suspicious = ["nc", "netcat", "meterpreter"]

    for proc in psutil.process_iter(['name']):
        try:
            if proc.info['name'] and proc.info['name'].lower() in suspicious:
                result += f"Suspicious Process Found: {proc.info['name']}\n"
        except:
            pass

    return result