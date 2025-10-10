# detection/Firewall_Port_Scan_hardened.py
import asyncio
import datetime
import ipaddress
import math
from collections import defaultdict, deque, Counter
from typing import List, Dict, Any, Tuple, Optional
from psycopg.types.json import Json
from collector.db import init_db  # your existing DB init
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("portscan-detector")

# ---------- Configuration ----------
# Tuning knobs: adjust to your environment
CONFIG = {
    # primary per-destination detection: many unique dst ports seen against one dst within short window
    "per_dst": {"threshold": 20, "window_seconds": 60},

    # distributed scan detection: single src hitting many distinct dst IPs (any port)
    "distributed": {"threshold": 50, "window_seconds": 300},

    # stealthy slow scans: smaller threshold but over longer time
    "slow_stealth": {"threshold": 10, "window_seconds": 3600, "min_unique_ports": 5},

    # aggregated across-destinations distinct ports (when attacker cycles through many hosts)
    "cross_dst_ports": {"threshold": 100, "window_seconds": 600},

    # dedupe alerts within X seconds to avoid repeats
    "alert_dedupe_seconds": 300,

    # whitelists/blacklists
    "whitelist_src_cidrs": ["10.0.0.0/8", "192.168.0.0/16"],  # internal scanners
    "blacklist_src": [],

    # DB insert batch size
    "db_batch_size": 20,
}

# ---------- Helpers ----------
def ensure_dt(ts) -> datetime.datetime:
    """Normalize timestamp to datetime (UTC-aware if ISO Z present)."""
    if isinstance(ts, datetime.datetime):
        return ts if ts.tzinfo else ts.replace(tzinfo=datetime.timezone.utc)
    if isinstance(ts, str):
        try:
            # fromisoformat handles offsets but not trailing Z; convert Z to +00:00
            return datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except Exception:
            # try common formats
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
                try:
                    return datetime.datetime.strptime(ts, fmt).replace(tzinfo=datetime.timezone.utc)
                except Exception:
                    pass
    # fallback to now UTC
    return datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)

def is_whitelisted(src_ip: str) -> bool:
    if not src_ip:
        return False
    try:
        ip = ipaddress.ip_address(src_ip)
    except Exception:
        return False
    for cidr in CONFIG["whitelist_src_cidrs"]:
        try:
            if ip in ipaddress.ip_network(cidr):
                return True
        except Exception:
            continue
    return False

def normalize_ip(ip_str: Optional[str]) -> Optional[str]:
    if not ip_str:
        return None
    # Convert ipaddress objects to string if needed
    if hasattr(ip_str, 'compressed'):
        ip_str = str(ip_str)

    # strip port if present, support ipv6 in [..]:port format
    if isinstance(ip_str, str):
        if ip_str.startswith("[") and "]" in ip_str:
            return ip_str.split("]")[0].lstrip("[")
        if ":" in ip_str and ip_str.count(":") == 1:
            # could be IPv4:port
            return ip_str.split(":")[0]
    return str(ip_str)


def safe_int(x, default=None):
    try:
        return int(x)
    except Exception:
        return default

# ---------- Detection class (stateful, efficient) ----------
class PortScanDetector:
    """
    Stateful detector that:
      - tracks per-src -> per-dst unique ports in sliding windows (deque for time-ordered entries)
      - tracks per-src distinct destinations
      - tracks per-src distinct ports across destinations
      - uses exponential decay scoring to surface stealthy scans
    """

    def __init__(self):
        # map: src -> dst -> deque[(port:int, ts:datetime)]
        self.per_src_dst = defaultdict(lambda: defaultdict(deque))

        # map: src -> deque[(dst_ip, ts)]
        self.src_dsts = defaultdict(deque)

        # map: src -> deque[(port, ts)] across all dsts
        self.src_ports = defaultdict(deque)

        # last alert times for deduping { alert_id: last_ts }
        self.last_alert_time = {}

    # housekeeping: drop old entries beyond max window
    def _expire_old(self, src: str, now: datetime.datetime):
        # determine longest window we might need to keep
        max_window = max(
            CONFIG["per_dst"]["window_seconds"],
            CONFIG["distributed"]["window_seconds"],
            CONFIG["cross_dst_ports"]["window_seconds"],
            CONFIG["slow_stealth"]["window_seconds"]
        )

        # expire per_src_dst entries
        for dst, dq in list(self.per_src_dst.get(src, {}).items()):
            while dq and (now - dq[0][1]).total_seconds() > max_window:
                dq.popleft()
            if not dq:
                del self.per_src_dst[src][dst]
        if not self.per_src_dst[src]:
            self.per_src_dst.pop(src, None)

        # expire src_dsts
        dq = self.src_dsts.get(src)
        if dq:
            while dq and (now - dq[0][1]).total_seconds() > max_window:
                dq.popleft()
            if not dq:
                self.src_dsts.pop(src, None)

        # expire src_ports
        dq = self.src_ports.get(src)
        if dq:
            while dq and (now - dq[0][1]).total_seconds() > max_window:
                dq.popleft()
            if not dq:
                self.src_ports.pop(src, None)

    def _unique_ports_within(self, src: str, dst: str, window_seconds: int, now: datetime.datetime) -> set:
        dq = self.per_src_dst.get(src, {}).get(dst, deque())
        return {p for (p, t) in dq if (now - t).total_seconds() <= window_seconds}

    def _unique_dsts_within(self, src: str, window_seconds: int, now: datetime.datetime) -> set:
        dq = self.src_dsts.get(src, deque())
        return {dst for (dst, t) in dq if (now - t).total_seconds() <= window_seconds}

    def _unique_ports_cross_dst(self, src: str, window_seconds: int, now: datetime.datetime) -> set:
        dq = self.src_ports.get(src, deque())
        return {p for (p, t) in dq if (now - t).total_seconds() <= window_seconds}

    def _recent_activity_count(self, dq: deque, window_seconds: int, now: datetime.datetime) -> int:
        return sum(1 for (_, t) in dq if (now - t).total_seconds() <= window_seconds)

    def generate_alert_id(self, rule_name: str, src: str, dst: Optional[str]) -> str:
        return f"{rule_name}|{src}|{dst or 'any'}"

    def detect_from_logs(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Accepts normalized log dicts (same fields as before). Returns list of alert dicts.
        This function is synchronous for simplicity; it updates in-memory state.
        """
        alerts = []
        for log in logs:
            ts = ensure_dt(log.get("@timestamp"))
            now = ts
            src_ip = normalize_ip(log.get("source", {}).get("ip") or log.get("source_ip"))
            dst_ip = normalize_ip(log.get("destination", {}).get("ip") or log.get("destination_ip"))
            dst_port = safe_int(log.get("destination", {}).get("port") or log.get("destination_port"))
            proto = (log.get("protocol") or "").lower()
            event_cat = log.get("event", {}).get("category") or log.get("category") or ""
            raw = log.get("raw", {})

            # skip incomplete
            if not src_ip or not dst_ip or dst_port is None:
                continue

            # skip whitelisted srcs
            if is_whitelisted(src_ip) or src_ip in CONFIG["blacklist_src"]:
                continue

            # housekeeping
            self._expire_old(src_ip, now)

            # record per-src per-dst port attempt
            self.per_src_dst[src_ip][dst_ip].append((dst_port, now))

            # record src->dst occurrence
            self.src_dsts[src_ip].append((dst_ip, now))

            # record src->port across dsts
            self.src_ports[src_ip].append((dst_port, now))

            # --------------- Rule 1: Per-destination port flood (classic port scan) ---------------
            pconf = CONFIG["per_dst"]
            recent_unique_ports = self._unique_ports_within(src_ip, dst_ip, pconf["window_seconds"], now)
            if len(recent_unique_ports) >= pconf["threshold"]:
                rule = "Per-Destination Port Scan"
                alert_id = self.generate_alert_id(rule, src_ip, dst_ip)
                if not self._should_dedupe(alert_id, now):
                    score = self._score(len(recent_unique_ports), pconf["threshold"])
                    alerts.append(self._make_alert(
                        rule, src_ip, dst_ip, score, list(sorted(recent_unique_ports)), now, proto, event_cat, raw,
                        evidence=f"{len(recent_unique_ports)} unique ports in last {pconf['window_seconds']}s"
                    ))
                    self._mark_alert(alert_id, now)

            # --------------- Rule 2: Distributed scanning (many distinct dsts) ---------------
            dconf = CONFIG["distributed"]
            unique_dsts = self._unique_dsts_within(src_ip, dconf["window_seconds"], now)
            if len(unique_dsts) >= dconf["threshold"]:
                rule = "Distributed Scan (many destinations)"
                alert_id = self.generate_alert_id(rule, src_ip, None)
                if not self._should_dedupe(alert_id, now):
                    score = self._score(len(unique_dsts), dconf["threshold"])
                    alerts.append(self._make_alert(
                        rule, src_ip, None, score, [], now, proto, event_cat, raw,
                        evidence=f"{len(unique_dsts)} distinct destinations in last {dconf['window_seconds']}s",
                        extra={"unique_dsts": list(sorted(unique_dsts))}
                    ))
                    self._mark_alert(alert_id, now)

            # --------------- Rule 3: Cross-destination unique ports (attacker scans ports while rotating dsts) ---------------
            cconf = CONFIG["cross_dst_ports"]
            cross_ports = self._unique_ports_cross_dst(src_ip, cconf["window_seconds"], now)
            if len(cross_ports) >= cconf["threshold"]:
                rule = "Cross-Destination High Port Diversity"
                alert_id = self.generate_alert_id(rule, src_ip, None)
                if not self._should_dedupe(alert_id, now):
                    score = self._score(len(cross_ports), cconf["threshold"])
                    alerts.append(self._make_alert(
                        rule, src_ip, None, score, list(sorted(cross_ports)), now, proto, event_cat, raw,
                        evidence=f"{len(cross_ports)} unique ports across destinations in last {cconf['window_seconds']}s"
                    ))
                    self._mark_alert(alert_id, now)

            # --------------- Rule 4: Stealthy/slow scan detection (low volume but persistent / diverse) ---------------
            sconf = CONFIG["slow_stealth"]
            # count unique ports per-dst in longer window
            slow_ports = self._unique_ports_within(src_ip, dst_ip, sconf["window_seconds"], now)
            if len(slow_ports) >= sconf["min_unique_ports"]:
                # compute a "persistence score": sqrt(n_ports) * log(1 + attempts)
                attempts = self._recent_activity_count(self.per_src_dst[src_ip][dst_ip], sconf["window_seconds"], now)
                persistence_score = math.sqrt(len(slow_ports)) * math.log1p(attempts)
                if len(slow_ports) >= sconf["threshold"] or persistence_score > (sconf["threshold"] / 2):
                    rule = "Stealthy Slow Scan"
                    alert_id = self.generate_alert_id(rule, src_ip, dst_ip)
                    if not self._should_dedupe(alert_id, now):
                        score = float(persistence_score)
                        alerts.append(self._make_alert(
                            rule, src_ip, dst_ip, score, list(sorted(slow_ports)), now, proto, event_cat, raw,
                            evidence=f"{len(slow_ports)} unique ports over {sconf['window_seconds']}s (attempts={attempts})"
                        ))
                        self._mark_alert(alert_id, now)

        return alerts

    def _score(self, observed: int, threshold: int) -> float:
        # simple normalized score; can be improved with weights
        return min(10.0, 1.0 * observed / threshold * 5.0)

    def _should_dedupe(self, alert_id: str, now: datetime.datetime) -> bool:
        last = self.last_alert_time.get(alert_id)
        if last and (now - last).total_seconds() < CONFIG["alert_dedupe_seconds"]:
            return True
        return False

    def _mark_alert(self, alert_id: str, now: datetime.datetime):
        self.last_alert_time[alert_id] = now

    def _make_alert(self, rule: str, src: str, dst: Optional[str], score: float,
                    ports: List[int], ts: datetime.datetime, proto: str, category: str, raw: dict,
                    evidence: str = "", extra: dict = None) -> dict:
        return {
            "rule": rule,
            "@timestamp": ts.isoformat(),
            "source.ip": src,
            "destination.ip": dst,
            "ports": ports,
            "count": len(ports) if ports else None,
            "protocol": proto,
            "severity": self._severity_from_score(score),
            "score": score,
            "attack.technique": "port_scanning",
            "evidence": evidence,
            "event.category": category,
            "raw": raw,
            "extra": extra or {}
        }

    def _severity_from_score(self, score: float) -> str:
        if score >= 8:
            return "CRITICAL"
        if score >= 5:
            return "HIGH"
        if score >= 2.5:
            return "MEDIUM"
        return "LOW"

# ---------- Fetch firewall logs from DB ----------
async def fetch_firewall_logs(pool, limit=5000):
    """
    Fetch logs where category includes 'firewall' (or network events that include destination ports).
    Returns a list of normalized log dicts for detection functions.
    """
    logs = []
    try:
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute("""
                    SELECT timestamp, username, source_ip, destination_ip,
                           destination_port, protocol, category, message, raw
                    FROM logs
                    WHERE 'firewall' = ANY(category) OR 'network' = ANY(category)
                    ORDER BY timestamp DESC
                    LIMIT %s
                """, (limit,))
                rows = await cur.fetchall()

        for r in rows:
            raw = r[8] or {}
            # normalize shape: allow destination.port present or flat destination_port
            dst_ip = r[3]
            dst_port = r[4]
            logs.append({
                "@timestamp": r[0],
                "user": {"name": r[1]},
                "source": {"ip": r[2]},
                "destination": {"ip": dst_ip, "port": dst_port},
                "destination_ip": dst_ip,
                "destination_port": dst_port,
                "protocol": r[5],
                "event": {"category": r[6]},
                "message": r[7],
                "raw": raw
            })
    except Exception as e:
        logger.exception(f"[!] Error fetching firewall logs: {e}")
    return logs

# ---------- Insert alerts into DB (batched) ----------
async def insert_alerts_batch(pool, alerts: List[dict]):
    """
    Inserts alerts in batches. Adjust columns to match your schema.
    """
    if not alerts:
        return

    insert_sql = """
    INSERT INTO alerts (
        timestamp, rule, user_name, source_ip,
        attempt_count, severity, technique, raw, score, evidence
    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """

    # prepare params
    params_list = []
    for alert in alerts:
        ts_val = ensure_dt(alert.get("@timestamp"))
        params_list.append((
            ts_val,
            alert.get("rule"),
            None,  # no specific user for port scans
            alert.get("source.ip"),
            alert.get("count") or 0,
            alert.get("severity"),
            alert.get("attack.technique"),
            Json(alert),
            alert.get("score"),
            alert.get("evidence")
        ))

    try:
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                for i in range(0, len(params_list), CONFIG["db_batch_size"]):
                    batch = params_list[i:i + CONFIG["db_batch_size"]]
                    await cur.executemany(insert_sql, batch)
        logger.info(f"[*] Saved {len(alerts)} alerts to DB (batched).")
    except Exception as e:
        logger.exception(f"[!] Error inserting alerts into DB: {e}")
        for a in alerts:
            logger.debug("Alert data: %s", a)

# ---------- Main runner ----------
async def main():
    pool = await init_db()
    logs = await fetch_firewall_logs(pool, limit=5000)
    if not logs:
        logger.info("[*] No firewall/network logs found to analyze.")
        return

    detector = PortScanDetector()
    alerts = detector.detect_from_logs(logs)

    if alerts:
        # print and store
        for a in alerts:
            logger.warning("[ALERT] %s - Src:%s Dst:%s Ports:%s Count:%s Time:%s Severity:%s Score:%.2f",
                           a["rule"], a.get("source.ip"), a.get("destination.ip"), a.get("ports"),
                           a.get("count"), a.get("@timestamp"), a.get("severity"), float(a.get("score", 0)))
        await insert_alerts_batch(pool, alerts)
    else:
        logger.info("[*] No port scanning detected.")

if __name__ == "__main__":
    asyncio.run(main())
