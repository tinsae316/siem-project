import asyncio
import datetime
import ipaddress
import math
from collections import defaultdict, deque
from psycopg.types.json import Json
import argparse
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from collector.db import init_db

LAST_SCAN_FILE = "last_scan_portscan.txt"

# ---------- Config ----------
CONFIG = {
    "per_dst": {"threshold": 20, "window_seconds": 60},
    "distributed": {"threshold": 50, "window_seconds": 300},
    "slow_stealth": {"threshold": 10, "window_seconds": 3600, "min_unique_ports": 5},
    "cross_dst_ports": {"threshold": 100, "window_seconds": 600},
    "alert_dedupe_seconds": 300,
    "whitelist_src_cidrs": ["10.0.0.0/8", "192.168.0.0/16"],
    "blacklist_src": [],
}

# ---------- Helpers ----------
def ensure_dt(ts):
    if isinstance(ts, datetime.datetime):
        return ts if ts.tzinfo else ts.replace(tzinfo=datetime.timezone.utc)
    if isinstance(ts, str):
        # NOTE: This expects ISO format with optional Z/timezone
        return datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    return datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)

def normalize_ip(ip_str):
    if not ip_str:
        return None
    if isinstance(ip_str, str):
        if ip_str.startswith("[") and "]" in ip_str:
            return ip_str.split("]")[0].lstrip("[")
        if ":" in ip_str and ip_str.count(":") == 1:
            # Simple fix for IPs with port like '192.168.1.1:80'
            return ip_str.split(":")[0]
    return str(ip_str)

def is_whitelisted(src_ip):
    if not src_ip:
        return False
    try:
        ip = ipaddress.ip_address(src_ip)
    except Exception:
        return False
    for cidr in CONFIG["whitelist_src_cidrs"]:
        if ip in ipaddress.ip_network(cidr):
            return True
    return False

def safe_int(x, default=None):
    try:
        return int(x)
    except Exception:
        return default

# ---------- Stateful Detector ----------
class PortScanDetector:
    def __init__(self):
        self.per_src_dst = defaultdict(lambda: defaultdict(deque))
        self.src_dsts = defaultdict(deque)
        self.src_ports = defaultdict(deque)
        self.last_alert_time = {}

    def _expire_old(self, src, now):
        max_window = max(
            CONFIG["per_dst"]["window_seconds"],
            CONFIG["distributed"]["window_seconds"],
            CONFIG["cross_dst_ports"]["window_seconds"],
            CONFIG["slow_stealth"]["window_seconds"]
        )
        for dst, dq in list(self.per_src_dst.get(src, {}).items()):
            while dq and (now - dq[0][1]).total_seconds() > max_window:
                dq.popleft()
            if not dq:
                del self.per_src_dst[src][dst]
        if not self.per_src_dst[src]:
            self.per_src_dst.pop(src, None)

        for dq_name in [self.src_dsts, self.src_ports]:
            dq = dq_name.get(src)
            if dq:
                while dq and (now - dq[0][1]).total_seconds() > max_window:
                    dq.popleft()
                if not dq:
                    dq_name.pop(src, None)

    def _unique_ports_within(self, src, dst, window_seconds, now):
        return {p for (p, t) in self.per_src_dst.get(src, {}).get(dst, deque()) if (now - t).total_seconds() <= window_seconds}

    def _unique_dsts_within(self, src, window_seconds, now):
        return {dst for (dst, t) in self.src_dsts.get(src, deque()) if (now - t).total_seconds() <= window_seconds}

    def _unique_ports_cross_dst(self, src, window_seconds, now):
        return {p for (p, t) in self.src_ports.get(src, deque()) if (now - t).total_seconds() <= window_seconds}

    def _recent_activity_count(self, dq, window_seconds, now):
        return sum(1 for (_, t) in dq if (now - t).total_seconds() <= window_seconds)

    def generate_alert_id(self, rule_name, src, dst):
        return f"{rule_name}|{src}|{dst or 'any'}"

    def _score(self, observed, threshold):
        return min(10.0, 1.0 * observed / threshold * 5.0)

    def _should_dedupe(self, alert_id, now):
        last = self.last_alert_time.get(alert_id)
        return last and (now - last).total_seconds() < CONFIG["alert_dedupe_seconds"]

    def _mark_alert(self, alert_id, now):
        self.last_alert_time[alert_id] = now

    def _severity_from_score(self, score):
        if score >= 8: return "CRITICAL"
        if score >= 5: return "HIGH"
        if score >= 2.5: return "MEDIUM"
        return "LOW"

    def _make_alert(self, rule, src, dst, score, ports, ts, raw, evidence="", extra=None):
        return {
            "rule": rule,
            "@timestamp": ts.isoformat(),
            "source.ip": src,
            "destination.ip": dst,
            "ports": ports,
            "count": len(ports) if ports else None,
            "severity": self._severity_from_score(score),
            "score": score,
            "attack.technique": "port_scanning",
            "evidence": evidence,
            "raw": raw,
            "extra": extra or {}
        }

    def detect_from_logs(self, logs):
        alerts = []
        for log in logs:
            ts = ensure_dt(log.get("@timestamp"))
            now = ts
            src_ip = normalize_ip(log.get("source", {}).get("ip") or log.get("source_ip"))
            dst_ip = normalize_ip(log.get("destination", {}).get("ip") or log.get("destination_ip"))
            dst_port = safe_int(log.get("destination", {}).get("port") or log.get("destination_port"))
            raw = log.get("raw", {})

            if not src_ip or not dst_ip or dst_port is None:
                continue
            if is_whitelisted(src_ip) or src_ip in CONFIG["blacklist_src"]:
                continue

            self._expire_old(src_ip, now)
            self.per_src_dst[src_ip][dst_ip].append((dst_port, now))
            self.src_dsts[src_ip].append((dst_ip, now))
            self.src_ports[src_ip].append((dst_port, now))

            # --- Rule 1: Per-Destination ---
            pconf = CONFIG["per_dst"]
            recent_ports = self._unique_ports_within(src_ip, dst_ip, pconf["window_seconds"], now)
            if len(recent_ports) >= pconf["threshold"]:
                rule = "Per-Destination Port Scan"
                alert_id = self.generate_alert_id(rule, src_ip, dst_ip)
                if not self._should_dedupe(alert_id, now):
                    alerts.append(self._make_alert(rule, src_ip, dst_ip, self._score(len(recent_ports), pconf["threshold"]),
                                                   list(sorted(recent_ports)), now, raw,
                                                   evidence=f"{len(recent_ports)} unique ports in last {pconf['window_seconds']}s"))
                    self._mark_alert(alert_id, now)

            # --- Rule 2: Distributed ---
            dconf = CONFIG["distributed"]
            unique_dsts = self._unique_dsts_within(src_ip, dconf["window_seconds"], now)
            if len(unique_dsts) >= dconf["threshold"]:
                rule = "Distributed Scan (many destinations)"
                alert_id = self.generate_alert_id(rule, src_ip, None)
                if not self._should_dedupe(alert_id, now):
                    alerts.append(self._make_alert(rule, src_ip, None, self._score(len(unique_dsts), dconf["threshold"]),
                                                   [], now, raw,
                                                   evidence=f"{len(unique_dsts)} distinct destinations in last {dconf['window_seconds']}s",
                                                   extra={"unique_dsts": list(sorted(unique_dsts))}))
                    self._mark_alert(alert_id, now)

            # --- Rule 3: Cross-Dst ---
            cconf = CONFIG["cross_dst_ports"]
            cross_ports = self._unique_ports_cross_dst(src_ip, cconf["window_seconds"], now)
            if len(cross_ports) >= cconf["threshold"]:
                rule = "Cross-Destination High Port Diversity"
                alert_id = self.generate_alert_id(rule, src_ip, None)
                if not self._should_dedupe(alert_id, now):
                    alerts.append(self._make_alert(rule, src_ip, None, self._score(len(cross_ports), cconf["threshold"]),
                                                   list(sorted(cross_ports)), now, raw,
                                                   evidence=f"{len(cross_ports)} unique ports across destinations in last {cconf['window_seconds']}s"))
                    self._mark_alert(alert_id, now)

            # --- Rule 4: Slow/Stealth ---
            sconf = CONFIG["slow_stealth"]
            slow_ports = self._unique_ports_within(src_ip, dst_ip, sconf["window_seconds"], now)
            if len(slow_ports) >= sconf["min_unique_ports"]:
                attempts = self._recent_activity_count(self.per_src_dst[src_ip][dst_ip], sconf["window_seconds"], now)
                persistence_score = math.sqrt(len(slow_ports)) * math.log1p(attempts)
                if len(slow_ports) >= sconf["threshold"] or persistence_score > (sconf["threshold"]/2):
                    rule = "Stealthy Slow Scan"
                    alert_id = self.generate_alert_id(rule, src_ip, dst_ip)
                    if not self._should_dedupe(alert_id, now):
                        alerts.append(self._make_alert(rule, src_ip, dst_ip, float(persistence_score),
                                                       list(sorted(slow_ports)), now, raw,
                                                       evidence=f"{len(slow_ports)} unique ports over {sconf['window_seconds']}s (attempts={attempts})"))
                        self._mark_alert(alert_id, now)

        return alerts

# ---------- DB helpers ----------
async def ensure_alerts_table(pool):
    create_sql = """
    CREATE TABLE IF NOT EXISTS alerts (
        id SERIAL PRIMARY KEY,
        timestamp TIMESTAMPTZ NOT NULL,
        rule TEXT NOT NULL,
        username TEXT,
        source_ip INET,
        count INT,
        severity TEXT,
        attack_technique TEXT,
        raw JSONB,
        UNIQUE (timestamp, rule, source_ip)
    );
    """
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(create_sql)

async def insert_alert_into_db(pool, alert: dict):
    # FIX APPLIED HERE: Changed 'username' to 'user_name' in both the SQL and the params dictionary.
    insert_sql = """
    INSERT INTO alerts (
        timestamp, rule, user_name, source_ip,
        attempt_count, severity, technique, raw
    ) VALUES (%(timestamp)s, %(rule)s, %(user_name)s, %(source_ip)s,
              %(attempt_count)s, %(severity)s, %(technique)s, %(raw)s)
    ON CONFLICT (timestamp, rule, source_ip) DO NOTHING;
    """
    ts_val = ensure_dt(alert.get("@timestamp"))
    params = {
        "timestamp": ts_val,
        "rule": alert.get("rule"),
        # FIX: Changed parameter key to 'user_name'
        "user_name": None,
        "source_ip": alert.get("source.ip"),
        # Mapping 'count' from alert payload to 'attempt_count' database column
        "attempt_count": alert.get("count"),
        "severity": alert.get("severity"),
        "technique": alert.get("attack.technique"),
        # The full alert payload, including 'score' and 'evidence', is stored here
        "raw": Json(alert)
    }
    try:
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(insert_sql, params)
        # The success log is now reached if the insert succeeds
        print(f"[*] Alert saved: {alert.get('rule')} - Src: {alert.get('source.ip')} Dst: {alert.get('destination.ip')}")
    except Exception as e:
        # Added more explicit logging for troubleshooting future DB errors
        print(f"[!] **CRITICAL DB ERROR** inserting alert: {e}")
        print("Alert data:", alert)


# ---------- Fetch firewall logs ----------
async def fetch_firewall_logs(pool, limit=5000, since=None):
    logs = []
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            if since:
                await cur.execute("""
                    SELECT timestamp, username, source_ip, destination_ip,
                           destination_port, protocol, category, message, raw
                    FROM logs
                    WHERE ('firewall' = ANY(category) OR 'network' = ANY(category))
                      AND timestamp > %s
                    ORDER BY timestamp ASC
                    LIMIT %s
                """, (since, limit))
            else:
                await cur.execute("""
                    SELECT timestamp, username, source_ip, destination_ip,
                           destination_port, protocol, category, message, raw
                    FROM logs
                    WHERE 'firewall' = ANY(category) OR 'network' = ANY(category)
                    ORDER BY timestamp ASC
                    LIMIT %s
                """, (limit,))
            rows = await cur.fetchall()

    for r in rows:
        logs.append({
            "@timestamp": r[0],
            "user": {"name": r[1]},
            "source": {"ip": r[2]},
            "destination": {"ip": r[3], "port": r[4]},
            "destination_ip": r[3],
            "destination_port": r[4],
            "protocol": r[5],
            "event": {"category": r[6]},
            "message": r[7],
            "raw": r[8] or {}
        })
    return logs

# ---------- Last scan helpers ----------
def get_last_scan_time():
    if os.path.exists(LAST_SCAN_FILE):
        with open(LAST_SCAN_FILE, "r") as f:
            return datetime.datetime.fromisoformat(f.read().strip())
    return None

def set_last_scan_time(ts):
    with open(LAST_SCAN_FILE, "w") as f:
        f.write(ts.isoformat())

# ---------- Main runner ----------
async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--full-scan", action="store_true")
    args = parser.parse_args()

    pool = await init_db()
    await ensure_alerts_table(pool)

    detector = PortScanDetector()

    if args.full_scan:
        print("[*] Starting full scan of all firewall logs...")
        logs = await fetch_firewall_logs(pool, limit=5000, since=None)
        alerts = detector.detect_from_logs(logs)
        for a in alerts:
            # The in-memory check already ensures these are non-deduplicated
            print(f"[ALERT] {a['rule']} Src:{a['source.ip']} Dst:{a['destination.ip']} Ports:{a.get('ports')} "
                  f"Count:{a.get('count')} Time:{a.get('@timestamp')} Severity:{a.get('severity')}")
            await insert_alert_into_db(pool, a)
        return

    while True:
        scan_time = datetime.datetime.now(datetime.timezone.utc)
        last_scan = get_last_scan_time()
        
        # Fetch logs for the full largest window to maintain detection state
        max_window = max(c["window_seconds"] for c in CONFIG.values() if isinstance(c, dict) and "window_seconds" in c)
        lookback_time = scan_time - datetime.timedelta(seconds=max_window + 60) # A little extra buffer
        
        # Clear state (or rely on expire_old) before running detect_from_logs on the lookback window
        # Note: expire_old handles internal state cleanup based on the timestamp of the incoming logs
        
        logs = await fetch_firewall_logs(pool, limit=5000, since=lookback_time)
        alerts = detector.detect_from_logs(logs)
        
        if alerts:
            for a in alerts:
                # The in-memory check already ensures these are non-deduplicated
                print(f"[ALERT] {a['rule']} Src:{a['source.ip']} Dst:{a['destination.ip']} Ports:{a.get('ports')} "
                      f"Count:{a.get('count')} Time:{a.get('@timestamp')} Severity:{a.get('severity')}")
                await insert_alert_into_db(pool, a)
        else:
            print(f"[{scan_time.isoformat()}] No port scanning detected.")

        set_last_scan_time(scan_time)
        await asyncio.sleep(40)

if __name__ == "__main__":
    asyncio.run(main())