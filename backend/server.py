from flask import Flask, send_from_directory
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import threading, time, psutil, os
from scanner import scan_host, save_report

app = Flask(__name__, static_folder="../frontend")
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="gevent")

scan_state    = {"running": False}
traffic_state = {"running": False}

@app.route("/")
def index():
    return send_from_directory("../frontend", "index.html")

def traffic_loop():
    prev = psutil.net_io_counters()
    while traffic_state["running"]:
        time.sleep(1)
        curr = psutil.net_io_counters()
        dl = round((curr.bytes_recv - prev.bytes_recv) * 8 / 1024, 2)
        ul = round((curr.bytes_sent - prev.bytes_sent) * 8 / 1024, 2)
        pkts_in  = curr.packets_recv - prev.packets_recv
        pkts_out = curr.packets_sent - prev.packets_sent
        errin    = curr.errin  - prev.errin
        errout   = curr.errout - prev.errout
        dropin   = curr.dropin - prev.dropin

        connections = []
        try:
            for c in psutil.net_connections(kind='inet'):
                if c.status == 'ESTABLISHED' and c.raddr:
                    connections.append({
                        "local_ip":    c.laddr.ip,
                        "local_port":  c.laddr.port,
                        "remote_ip":   c.raddr.ip,
                        "remote_port": c.raddr.port,
                        "status":      c.status
                    })
        except:
            pass

        collision = (errin + errout + dropin) > 0 or \
                    (dl < 10 and ul < 10 and len(connections) > 3)

        socketio.emit("traffic_update", {
            "dl":          dl,
            "ul":          ul,
            "pkts_in":     pkts_in,
            "pkts_out":    pkts_out,
            "errin":       errin,
            "errout":      errout,
            "dropin":      dropin,
            "collision":   collision,
            "connections": connections[:10]
        })
        prev = curr

@socketio.on("connect")
def on_connect():
    if not traffic_state["running"]:
        traffic_state["running"] = True
        threading.Thread(target=traffic_loop, daemon=True).start()

@socketio.on("start_scan")
def handle_start_scan(data):
    if scan_state["running"]:
        return
    host = data.get("host", "127.0.0.1")
    ps   = int(data.get("port_start", 1))
    pe   = int(data.get("port_end", 1024))
    scan_state["running"] = True
    emit("scan_started", {"host": host})

    def run():
        def cb(r):
            if scan_state["running"]:
                socketio.emit("port_found", r)
        ports = scan_host(host, (ps, pe), callback=cb)
        save_report(host, ports)
        scan_state["running"] = False
        socketio.emit("scan_complete", {
            "total": len(ports),
            "ports": ports
        })
    threading.Thread(target=run, daemon=True).start()

@socketio.on("stop_scan")
def handle_stop_scan():
    scan_state["running"] = False
    emit("scan_stopped", {})

if __name__ == "__main__":
    socketio.run(app, host="127.0.0.1", port=5000, debug=False)