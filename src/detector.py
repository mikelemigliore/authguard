
import json
from collections import defaultdict, deque
from datetime import timedelta
from typing import List, Dict, Any
from src.parser import LogEntry


def load_rules(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def detect_bruteforce(entries: List[LogEntry], rules: Dict[str, Any]) -> List[Dict[str, Any]]:
    alerts = []
    threshold = rules["bruteforce"]["fail_threshold"]
    window = timedelta(seconds=rules["bruteforce"]["time_window_seconds"])

    attempts: Dict[str, deque] = defaultdict(deque)

    for entry in entries:
        if entry.status != "FAIL":
            continue

        attempts[entry.ip].append(entry.timestamp)

        while attempts[entry.ip] and (entry.timestamp - attempts[entry.ip][0]) > window:
            attempts[entry.ip].popleft()

        if len(attempts[entry.ip]) >= threshold:
            alerts.append({
                "type": "bruteforce",
                "ip": entry.ip,
                "timestamp": entry.timestamp.isoformat(),
                "fail_count": len(attempts[entry.ip]),
                "window_seconds": rules["bruteforce"]["time_window_seconds"]
            })

    return alerts


def detect_password_spraying(entries: List[LogEntry], rules: Dict[str, Any]) -> List[Dict[str, Any]]:
    alerts = []
    window = timedelta(seconds=rules["password_spraying"]["time_window_seconds"])
    user_threshold = rules["password_spraying"]["user_threshold"]

    attempts: Dict[str, deque] = defaultdict(deque)

    for entry in entries:
        if entry.status != "FAIL":
            continue

        attempts[entry.ip].append((entry.timestamp, entry.user))

        while attempts[entry.ip] and (entry.timestamp - attempts[entry.ip][0][0]) > window:
            attempts[entry.ip].popleft()

        unique_users = {user for (_, user) in attempts[entry.ip]}

        if len(unique_users) >= user_threshold:
            alerts.append({
                "type": "password_spraying",
                "ip": entry.ip,
                "timestamp": entry.timestamp.isoformat(),
                "unique_users": list(unique_users),
                "window_seconds": rules["password_spraying"]["time_window_seconds"]
            })

    return alerts


def detect_credential_stuffing(entries: List[LogEntry], rules: Dict[str, Any]) -> List[Dict[str, Any]]:
    alerts = []
    fail_threshold = rules["credential_stuffing"]["fail_threshold"]
    success_threshold = rules["credential_stuffing"]["success_threshold"]
    window = timedelta(seconds=rules["credential_stuffing"]["time_window_seconds"])

    events: Dict[str, deque] = defaultdict(deque)

    for entry in entries:
        events[entry.ip].append((entry.timestamp, entry.status))

        while events[entry.ip] and (entry.timestamp - events[entry.ip][0][0]) > window:
            events[entry.ip].popleft()

        fails = sum(1 for (_, s) in events[entry.ip] if s == "FAIL")
        successes = sum(1 for (_, s) in events[entry.ip] if s == "SUCCESS")

        if fails >= fail_threshold and successes >= success_threshold:
            alerts.append({
                "type": "credential_stuffing",
                "ip": entry.ip,
                "timestamp": entry.timestamp.isoformat(),
                "fail_count": fails,
                "success_count": successes,
                "window_seconds": rules["credential_stuffing"]["time_window_seconds"]
            })

    return alerts


def run_detection(entries: List[LogEntry], rules_path: str) -> List[Dict[str, Any]]:
    rules = load_rules(rules_path)

    alerts = []
    alerts.extend(detect_bruteforce(entries, rules))
    alerts.extend(detect_password_spraying(entries, rules))
    alerts.extend(detect_credential_stuffing(entries, rules))

    return alerts
