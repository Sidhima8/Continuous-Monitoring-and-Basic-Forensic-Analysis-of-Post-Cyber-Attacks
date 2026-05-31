import platform
import psutil

def system_info():
    info = ""

    info += f"System: {platform.system()}\n"
    info += f"Node Name: {platform.node()}\n"
    info += f"Release: {platform.release()}\n"
    info += f"Processor: {platform.processor()}\n\n"

    info += f"CPU Usage: {psutil.cpu_percent()}%\n"
    info += f"Memory Usage: {psutil.virtual_memory().percent}%\n"

    return info