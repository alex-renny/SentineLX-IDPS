import psutil
import platform
import socket
from datetime import datetime
import json


def get_system_stats():
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage("/")

    return {
        "timestamp": datetime.now().isoformat(),
        "hostname": socket.gethostname(),
        "platform": platform.system(),
        "cpu": {
            "usage": psutil.cpu_percent(interval=0.5),
            "cores": psutil.cpu_count(logical=True),
        },
        "memory": {
            "usage": memory.percent,
            "total": round(memory.total / (1024 ** 3), 2),
            "used": round(memory.used / (1024 ** 3), 2),
            "available": round(memory.available / (1024 ** 3), 2),
        },
        "disk": {
            "usage": disk.percent,
            "total": round(disk.total / (1024 ** 3), 2),
            "used": round(disk.used / (1024 ** 3), 2),
            "free": round(disk.free / (1024 ** 3), 2),
        },
    }


def get_processes(limit=10):
    processes = []

    for process in psutil.process_iter(
        ["pid", "name", "username", "cpu_percent", "memory_percent"]
    ):
        try:
            info = process.info

            processes.append({
                "pid": info["pid"],
                "name": info["name"] or "Unknown",
                "username": info["username"] or "Unknown",
                "cpu": round(info["cpu_percent"] or 0, 2),
                "memory": round(info["memory_percent"] or 0, 2),
            })

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    processes.sort(
        key=lambda process: process["cpu"],
        reverse=True
    )

    return processes[:limit]


if __name__ == "__main__":
    result = {
        "system": get_system_stats(),
        "processes": get_processes()
    }

    print(json.dumps(result))