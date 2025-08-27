# wifi_checker.py
# Public WiFi Safety Checker — GUI tool with risk score, captive portal & SSL checks
# MIT License (c) 2025 Tanmay Sanjay Patil

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import socket, subprocess, platform, json, time
from datetime import datetime

# Third-party
try:
    import requests
except Exception:
    requests = None

# Optional: speed test (will be skipped if not installed)
try:
    import speedtest
except Exception:
    speedtest = None


# ----------------------------- Helpers -----------------------------

def run_cmd(cmd: str) -> str:
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        return out.decode(errors="ignore")
    except Exception:
        return ""


def detect_encryption(ssid: str) -> str:
    """
    Best-effort detection of Wi-Fi encryption for the given SSID.
    Works on: Windows (netsh), Linux (nmcli), macOS (airport).
    Returns one of: 'WPA3', 'WPA2', 'OPEN', 'WEP', 'UNKNOWN'
    """
    system = platform.system().lower()

    if "windows" in system:
        # netsh wlan show networks mode=bssid
        out = run_cmd('netsh wlan show networks mode=bssid')
        block = []
        current = []
        for line in out.splitlines():
            if line.strip().lower().startswith("ssid"):
                if current:
                    block.append("\n".join(current))
                    current = []
            current.append(line)
        if current:
            block.append("\n".join(current))

        for b in block:
            if ssid.lower() in b.lower():
                # Look for Authentication or Encryption info
                if "WPA3" in b.upper():
                    return "WPA3"
                if "WPA2" in b.upper():
                    return "WPA2"
                if "WEP" in b.upper():
                    return "WEP"
                if "Open" in b or "OPEN" in b:
                    return "OPEN"
        return "UNKNOWN"

    if "linux" in system:
        # nmcli -f SSID,SECURITY dev wifi
        out = run_cmd('nmcli -f SSID,SECURITY dev wifi')
        for line in out.splitlines():
            parts = [p.strip() for p in line.split()]
            if not parts:
                continue
            if ssid.lower() in line.lower():
                sec = line.split()[-1] if len(line.split()) > 1 else ""
                up = sec.upper()
                if "WPA3" in up:
                    return "WPA3"
                if "WPA2" in up:
                    return "WPA2"
                if "WEP" in up:
                    return "WEP"
                if up in ("--", "NONE"):
                    return "OPEN"
        return "UNKNOWN"

    if "darwin" in system:  # macOS
        # airport -s (lists SSIDs and security)
        airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
        out = run_cmd(f'"{airport}" -s')
        for line in out.splitlines()[1:]:
            if ssid.lower() in line.lower():
                up = line.upper()
                if "WPA3" in up:
                    return "WPA3"
                if "WPA2" in up:
                    return "WPA2"
                if "WEP" in up:
                    return "WEP"
                if "NONE" in up:
                    return "OPEN"
        return "UNKNOWN"

    return "UNKNOWN"


def check_dns() -> dict:
    """
    Resolve a few popular domains. If resolution fails or all resolve to the same odd IP,
    flag as suspicious. (Lightweight heuristic)
    """
    domains = ["google.com", "github.com", "example.com"]
    results = {}
    ips = []
    ok = True
    for d in domains:
        try:
            ip = socket.gethostbyname(d)
            results[d] = ip
            ips.append(ip)
        except Exception as e:
            results[d] = f"RESOLVE_FAIL: {e}"
            ok = False

    suspicious = False
    if len(set(ips)) == 1 and len(ips) >= 2:
        # All different domains resolved to the same IP — could be captive portal / DNS hijack
        suspicious = True

    return {
        "ok": ok and not suspicious,
        "details": results,
        "reason": "Multiple domains resolved to identical IP (possible hijack)" if suspicious else ("OK" if ok else "One or more domains failed to resolve"),
    }


def check_captive_portal() -> dict:
    """
    Try to fetch http://example.com (HTTP). If it redirects to another host or HTTPS with a strange host,
    likely captive portal.
    """
    if requests is None:
        return {"ok": False, "reason": "requests not installed", "redirected": None}

    try:
        r = requests.get("http://example.com", allow_redirects=True, timeout=5)
        chain = [resp.url for resp in r.history] + [r.url]
        # If final URL host isn't example.com for plain HTTP, probably captive
        final = r.url
        captive = ("example.com" not in final.lower()) or len(r.history) > 0
        return {
            "ok": not captive,
            "reason": "Redirected (possible captive portal)" if captive else "No redirect detected",
            "redirected": chain if len(chain) > 1 else None
        }
    except Exception as e:
        # On some networks, HTTP is blocked or tampered — treat as suspicious but not fatal
        return {"ok": False, "reason": f"HTTP fetch failed: {e}", "redirected": None}


def check_ssl_sanity() -> dict:
    """
    Try a few HTTPS sites with certificate verification.
    """
    if requests is None:
        return {"ok": False, "reason": "requests not installed"}

    sites = ["https://google.com", "https://github.com"]
    try:
        for s in sites:
            r = requests.get(s, timeout=6)  # verify=True by default
            if r.status_code >= 500:
                return {"ok": False, "reason": f"Bad status from {s}: {r.status_code}"}
        return {"ok": True, "reason": "Valid HTTPS connections"}
    except requests.exceptions.SSLError as e:
        return {"ok": False, "reason": f"SSL error: {e}"}
    except Exception as e:
        return {"ok": False, "reason": f"HTTPS check failed: {e}"}


def run_speed_test() -> dict:
    """
    Optional speed & latency check using speedtest module.
    """
    if speedtest is None:
        return {"ok": False, "reason": "speedtest module not installed", "ping_ms": None, "down_mbps": None, "up_mbps": None}

    try:
        st = speedtest.Speedtest()
        st.get_best_server()
        ping = st.results.ping
        down = st.download() / 1e6
        up = st.upload() / 1e6
        return {"ok": True, "reason": "Speed test OK", "ping_ms": round(ping, 1), "down_mbps": round(down, 2), "up_mbps": round(up, 2)}
    except Exception as e:
        return {"ok": False, "reason": f"Speed test failed: {e}", "ping_ms": None, "down_mbps": None, "up_mbps": None}


def compute_risk(encryption: str, dns: dict, captive: dict, sslc: dict, speed: dict) -> dict:
    """
    Score 0-100 (higher is safer). Deduct points for risky findings.
    """
    score = 100
    notes = []

    # Encryption
    if encryption == "OPEN":
        score -= 40; notes.append("Open network (no encryption)")
    elif encryption == "WEP":
        score -= 30; notes.append("WEP is obsolete/weak")
    elif encryption == "WPA2":
        score -= 10; notes.append("WPA2 is OK but older than WPA3")
    elif encryption == "UNKNOWN":
        score -= 10; notes.append("Encryption unknown")

    # Captive portal
    if not captive.get("ok", True):
        score -= 15; notes.append("Captive portal / HTTP redirect behavior")

    # DNS
    if not dns.get("ok", True):
        score -= 20; notes.append("DNS resolution anomaly")

    # SSL sanity
    if not sslc.get("ok", True):
        score -= 25; notes.append("HTTPS/SSL issues")

    # Speed & latency heuristics
    if speed.get("ok"):
        if speed.get("down_mbps", 100) < 2:
            score -= 10; notes.append("Very slow download speed")
        if speed.get("ping_ms", 0) > 150:
            score -= 10; notes.append("High latency")
    else:
        notes.append("Speed test unavailable: " + (speed.get("reason") or "unknown"))

    # Clamp
    score = max(0, min(100, score))

    # Verdict
    if score >= 80:
        verdict = "✅ Safe"
    elif score >= 60:
        verdict = "🟡 Moderate"
    else:
        verdict = "❌ Risky"

    return {"score": score, "verdict": verdict, "notes": notes}


# ----------------------------- GUI Actions -----------------------------

def run_checks():
    ssid = ssid_var.get().strip()
    if not ssid:
        messagebox.showwarning("Input needed", "Enter the Wi-Fi SSID (network name).")
        return

    output.configure(state="normal")
    output.delete("1.0", tk.END)

    start = time.time()
    output.insert(tk.END, f"➡️ Checking Wi-Fi: {ssid}\n")
    output.insert(tk.END, "Running tests...\n\n")
    root.update_idletasks()

    enc = detect_encryption(ssid)
    output.insert(tk.END, f"🔐 Encryption: {enc}\n")

    dns = check_dns()
    output.insert(tk.END, f"🧭 DNS: {'OK' if dns['ok'] else 'Suspicious'} — {dns['reason']}\n")
    for k, v in dns["details"].items():
        output.insert(tk.END, f"   • {k} → {v}\n")

    captive = check_captive_portal()
    ok_capt = "No captive portal" if captive["ok"] else "Captive behavior / blocked"
    output.insert(tk.END, f"🚧 Captive Portal: {ok_capt} — {captive['reason']}\n")
    if captive.get("redirected"):
        output.insert(tk.END, f"   • Redirect chain: {captive['redirected']}\n")

    sslc = check_ssl_sanity()
    output.insert(tk.END, f"🔒 HTTPS/SSL: {'OK' if sslc['ok'] else 'Issue'} — {sslc['reason']}\n")

    speed_info = {"ok": False, "reason": "Skipped (enable in Advanced)", "ping_ms": None, "down_mbps": None, "up_mbps": None}
    if speedtest_toggle.get():
        output.insert(tk.END, "⏱️ Running speed test (optional)... This may take ~30–60s.\n")
        root.update_idletasks()
        speed_info = run_speed_test()
        if speed_info["ok"]:
            output.insert(tk.END, f"   • Ping: {speed_info['ping_ms']} ms, Down: {speed_info['down_mbps']} Mbps, Up: {speed_info['up_mbps']} Mbps\n")
        else:
            output.insert(tk.END, f"   • Speed test unavailable — {speed_info['reason']}\n")

    risk = compute_risk(enc, dns, captive, sslc, speed_info)
    output.insert(tk.END, "\n===============================\n")
    output.insert(tk.END, f"Risk Score: {risk['score']}/100  {risk['verdict']}\n")
    if risk["notes"]:
        output.insert(tk.END, "Notes:\n")
        for n in risk["notes"]:
            output.insert(tk.END, f"   • {n}\n")
    elapsed = round(time.time() - start, 1)
    output.insert(tk.END, f"\nDone in {elapsed}s.\n")
    output.configure(state="disabled")

    # Save results in memory for export
    global last_report
    last_report = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "ssid": ssid,
        "encryption": enc,
        "dns": dns,
        "captive_portal": captive,
        "ssl_check": sslc,
        "speed_test": speed_info,
        "risk": risk,
        "elapsed_seconds": elapsed,
    }


def export_report():
    if not last_report:
        messagebox.showinfo("No report", "Run a check first, then export.")
        return

    ftypes = [("JSON file", "*.json"), ("Text file", "*.txt")]
    path = filedialog.asksaveasfilename(title="Save report", defaultextension=".json", filetypes=ftypes)
    if not path:
        return

    try:
        if path.lower().endswith(".txt"):
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"Public WiFi Safety Checker — Report\n")
                f.write(f"Timestamp: {last_report['timestamp']}\n")
                f.write(f"SSID: {last_report['ssid']}\n")
                f.write(f"Encryption: {last_report['encryption']}\n\n")
                f.write(f"DNS: {'OK' if last_report['dns']['ok'] else 'Suspicious'} — {last_report['dns']['reason']}\n")
                for k, v in last_report['dns']['details'].items():
                    f.write(f"   • {k} → {v}\n")
                f.write(f"\nCaptive Portal: {'No' if last_report['captive_portal']['ok'] else 'Yes/Blocked'} — {last_report['captive_portal']['reason']}\n")
                if last_report['captive_portal'].get("redirected"):
                    f.write(f"   • Redirect chain: {last_report['captive_portal']['redirected']}\n")
                f.write(f"\nHTTPS/SSL: {'OK' if last_report['ssl_check']['ok'] else 'Issue'} — {last_report['ssl_check']['reason']}\n")
                sp = last_report['speed_test']
                if sp.get("ok"):
                    f.write(f"\nSpeed: Ping {sp['ping_ms']} ms, Down {sp['down_mbps']} Mbps, Up {sp['up_mbps']} Mbps\n")
                else:
                    f.write(f"\nSpeed: {sp.get('reason','N/A')}\n")
                f.write("\n-------------------------------\n")
                f.write(f"Risk Score: {last_report['risk']['score']}/100  {last_report['risk']['verdict']}\n")
                if last_report['risk']['notes']:
                    f.write("Notes:\n")
                    for n in last_report['risk']['notes']:
                        f.write(f"   • {n}\n")
                f.write(f"\nElapsed: {last_report['elapsed_seconds']}s\n")
        else:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(last_report, f, indent=2)
        messagebox.showinfo("Saved", f"Report saved to:\n{path}")
    except Exception as e:
        messagebox.showerror("Error", f"Could not save report:\n{e}")


# ----------------------------- GUI -----------------------------

last_report = None

root = tk.Tk()
root.title("Public WiFi Safety Checker")
root.geometry("720x560")

top = ttk.Frame(root)
top.pack(fill="x", padx=12, pady=10)

ttk.Label(top, text="Wi-Fi SSID:").pack(side="left")
ssid_var = tk.StringVar()
ssid_entry = ttk.Entry(top, textvariable=ssid_var, width=40)
ssid_entry.pack(side="left", padx=8)

speedtest_toggle = tk.BooleanVar(value=False)
ttk.Checkbutton(top, text="Run speed test (optional)", variable=speedtest_toggle).pack(side="left", padx=8)

ttk.Button(top, text="Check Safety", command=run_checks).pack(side="left", padx=8)
ttk.Button(top, text="Export Report", command=export_report).pack(side="left", padx=8)

output = tk.Text(root, height=24, wrap="word")
output.pack(fill="both", expand=True, padx=12, pady=8)
output.configure(state="disabled")

ttk.Label(root, text="Tip: Install 'requests' and optionally 'speedtest-cli' for full checks.").pack(pady=(0,10))

root.mainloop()
