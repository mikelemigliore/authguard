# src/parser.py

import json
from dataclasses import dataclass
from datetime import datetime
from typing import List


@dataclass
class LogEntry:
  timestamp: datetime
  ip: str
  user: str
  status: str  # "FAIL" or "SUCCESS"


def parse_log_line(line: str) -> LogEntry | None:
  """
  Parse a single JSON log line into a LogEntry object.
  Returns None if the line is empty or invalid.
  """
  line = line.strip()
  if not line:
    return None

  try:
    data = json.loads(line)
    ts = datetime.fromisoformat(data["timestamp"])
    return LogEntry(
      timestamp=ts,
      ip=data["ip"],
      user=data["user"],
      status=data["status"].upper()
    )
  except (json.JSONDecodeError, KeyError, ValueError):
    # In a real system you'd log this; here we just skip bad lines.
    return None


def load_logs(path: str) -> List[LogEntry]:
  """
  Load all logs from a file and return a list of LogEntry objects.
  """
  entries: List[LogEntry] = []

  with open(path, "r", encoding="utf-8") as f:
    for line in f:
      entry = parse_log_line(line)
      if entry is not None:
        entries.append(entry)

  # Sort by time, just in case the file isn't already ordered
  entries.sort(key=lambda e: e.timestamp)
  return entries