# collector/parser.py
import re
import json
from collector.schemas import LogSchema
from pydantic import ValidationError
from collector.utils import utc_now_iso, geo_lookup, resolve_hostname

def parse_json_log(line: str):
    """
    Parse a JSON formatted log line.
    """
    try:
        # Attempt to parse the line as JSON
        log_data = json.loads(line)
        # Use Pydantic to validate the structure
        validated_log = LogSchema.parse_obj(log_data)
        return validated_log.dict()
    except (json.JSONDecodeError, ValidationError) as e:
        # If parsing or validation fails, it's not a valid JSON log.
        print(f"[!] JSON parsing or validation failed: {e}")
        return None

def parse_ssh_auth_log(line: str):
    """
    Parse SSH authentication logs (failed login attempts)
    Example: 'Sep  2 15:21:30 server01 sshd[1234]: Failed password for admin from 42.236.12.235 port 22 ssh2'
    """
    match = re.search(r"Failed password for (\w+) from ([\d.]+) port (\d+)", line)
    if match:
        user, ip, port = match.groups()
        geo = geo_lookup(ip)
        hostname = resolve_hostname(ip)
        return {
            "timestamp": utc_now_iso(),
            "event": {"category": ["authentication"], "outcome": "failure", "action": "login"},
            "host": {"hostname": "server01"},
            "source": {"ip": ip, "port": int(port), "geo": geo, "hostname": hostname},
            "user": {"name": user},
            "message": line.strip()
        }
    return None


def parse_web_access_log(line: str):
    """
    Parse simple Apache/Nginx access logs
    Example: '42.236.12.235 - - [02/Sep/2025:15:21:30 +0000] "POST /login HTTP/1.1" 401 234 "-" "Mozilla/5.0 ..."'
    """
    match = re.search(r'([\d.]+) - - \[.*?\] "(GET|POST|PUT|DELETE) (.*?) HTTP/[\d.]+" (\d{3}) (\d+).*"(.*?)"', line)
    if match:
        ip, method, path, status, size, user_agent = match.groups()
        geo = geo_lookup(ip)
        hostname = resolve_hostname(ip)
        outcome = "success" if status.startswith("2") else "failure"
        return {
            "timestamp": utc_now_iso(),
            "event": {"category": ["web"], "outcome": outcome, "action": "request"},
            "host": {"hostname": "webserver01"},
            "source": {"ip": ip, "geo": geo, "hostname": hostname},
            "http": {"request": {"method": method, "body.bytes": int(size)}, "response": {"status_code": int(status)}},
            "url": {"path": path},
            "user_agent": {"original": user_agent},
            "message": line.strip()
        }
    return None


def parse_firewall_log(line: str):
    """
    Parse firewall logs (syslog-style).
    Example:
    'Sep 25 10:15:32 firewall01 action=deny src=192.168.1.10 dst=10.0.0.5 dport=443 proto=TCP'
    """
    match = re.search(
        r"action=(\w+)\s+src=([\d.]+)\s+dst=([\d.]+)\s+dport=(\d+)\s+proto=(\w+)", 
        line
    )
    if match:
        action, src_ip, dst_ip, dst_port, proto = match.groups()
        geo = geo_lookup(src_ip)
        hostname = resolve_hostname(src_ip)
        return {
            "timestamp": utc_now_iso(),  # you could also parse syslog timestamp if needed
            "event": {"category": ["firewall"], "outcome": "success", "action": action},
            "host": {"hostname": "firewall01"},
            "source": {"ip": src_ip, "geo": geo, "hostname": hostname},
            "destination": {"ip": dst_ip, "port": int(dst_port)},
            "network": {"transport": proto},
            "message": line.strip()
        }
    return None


def parse_log_line(line: str):
    """
    Main entry point: tries multiple parsers in order
    """
    parsers = [parse_firewall_log, parse_ssh_auth_log, parse_web_access_log, parse_json_log ]
    for parser in parsers:
        result = parser(line)
        if result:
            return result
    return None
