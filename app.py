from flask import Flask, render_template, jsonify, request
import psutil
import socket
import threading
import time
import datetime
import os 

app = Flask(__name__)

# ─── Store traffic history for charts (last 30 readings) ───
traffic_history = {
    "labels": [],
    "bytes_sent": [],
    "bytes_recv": [],
    "packets_sent": [],
    "packets_recv": []
}
MAX_HISTORY = 30
_prev_io = psutil.net_io_counters()

def collect_traffic_history():
    """Background thread: collect network I/O every 2 seconds."""
    global _prev_io
    while True:
        time.sleep(2)
        io = psutil.net_io_counters()
        now = datetime.datetime.now().strftime("%H:%M:%S")

        sent_rate  = max(0, io.bytes_sent  - _prev_io.bytes_sent)
        recv_rate  = max(0, io.bytes_recv  - _prev_io.bytes_recv)
        psent_rate = max(0, io.packets_sent - _prev_io.packets_sent)
        precv_rate = max(0, io.packets_recv - _prev_io.packets_recv)
        _prev_io = io

        traffic_history["labels"].append(now)
        traffic_history["bytes_sent"].append(sent_rate)
        traffic_history["bytes_recv"].append(recv_rate)
        traffic_history["packets_sent"].append(psent_rate)
        traffic_history["packets_recv"].append(precv_rate)

        for key in traffic_history:
            if len(traffic_history[key]) > MAX_HISTORY:
                traffic_history[key].pop(0)

threading.Thread(target=collect_traffic_history, daemon=True).start()


# ─── Helper ───────────────────────────────────────────────
def fmt_bytes(b):
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if b < 1024:
            return f"{b:.2f} {unit}"
        b /= 1024
    return f"{b:.2f} PB"


def get_latency(host="8.8.8.8", port=53, timeout=2):
    try:
        start = time.time()
        s = socket.create_connection((host, port), timeout)
        s.close()
        return round((time.time() - start) * 1000, 2)
    except Exception:
        return None


# ─── API Endpoints ─────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/network-info")
def api_network_info():
    hostname = socket.gethostname()
    try:
        ip = socket.gethostbyname(hostname)
    except Exception:
        ip = "Unavailable"

    interfaces = []
    for iface, addrs in psutil.net_if_addrs().items():
        for a in addrs:
            if a.family == socket.AF_INET:
                interfaces.append({"name": iface, "ip": a.address, "netmask": a.netmask})

    return jsonify({
        "hostname": hostname,
        "ip": ip,
        "interfaces": interfaces
    })


@app.route("/api/traffic")
def api_traffic():
    io = psutil.net_io_counters()
    return jsonify({
        "bytes_sent":     io.bytes_sent,
        "bytes_recv":     io.bytes_recv,
        "packets_sent":   io.packets_sent,
        "packets_recv":   io.packets_recv,
        "bytes_sent_fmt": fmt_bytes(io.bytes_sent),
        "bytes_recv_fmt": fmt_bytes(io.bytes_recv)
    })


@app.route("/api/traffic-history")
def api_traffic_history():
    return jsonify(traffic_history)


@app.route("/api/internet-status")
def api_internet_status():
    latency = get_latency()
    return jsonify({
        "connected": latency is not None,
        "latency": latency if latency is not None else "N/A"
    })


@app.route("/api/cpu-mem")
def api_cpu_mem():
    return jsonify({
        "cpu": psutil.cpu_percent(interval=0.5),
        "memory": psutil.virtual_memory().percent,
        "memory_used": fmt_bytes(psutil.virtual_memory().used),
        "memory_total": fmt_bytes(psutil.virtual_memory().total)
    })


@app.route("/api/scan-ports", methods=["POST"])
def api_scan_ports():
    data = request.get_json(force=True) or {}
    target   = data.get("host", "127.0.0.1").strip()
    port_min = int(data.get("port_min", 1))
    port_max = int(data.get("port_max", 1024))

    # Safety cap
    if port_max - port_min > 2000:
        port_max = port_min + 2000

    results = []
    lock = threading.Lock()

    def scan(p):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.4)
            open_ = s.connect_ex((target, p)) == 0
            s.close()
            service = ""
            try:
                service = socket.getservbyport(p)
            except Exception:
                service = "unknown"
            with lock:
                results.append({"port": p, "status": "Open" if open_ else "Closed", "service": service})
        except Exception:
            with lock:
                results.append({"port": p, "status": "Error", "service": ""})

    threads = []
    for port in range(port_min, port_max + 1):
        t = threading.Thread(target=scan, args=(port,))
        threads.append(t)
        t.start()
        # throttle: max 200 concurrent threads
        if len(threads) >= 200:
            for t2 in threads:
                t2.join()
            threads = []

    for t in threads:
        t.join()

    results.sort(key=lambda x: x["port"])
    open_ports = [r for r in results if r["status"] == "Open"]
    return jsonify({"results": results, "open_count": len(open_ports), "target": target})


if __name__ == "__main__":
    print("=" * 50)
    print("  Network Monitor Dashboard")
    print("  Open: http://127.0.0.1:5000")
    print("=" * 50)
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False,
        use_reloader=False
        )
