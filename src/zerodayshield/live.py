"""Authorized live flow capture and anomaly scoring.

Only flow-level summaries and scores are persisted. Raw packets and endpoint IPs
are not written to the output file. Capture requires Npcap/administrator access
on Windows and must be limited to a network the operator may monitor.
"""

from __future__ import annotations

import argparse
import csv
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd

from .replay import score_frame

LOG = logging.getLogger("zerodayshield.live")
OUTPUT_COLUMNS = [
    "observed_at_utc",
    "model",
    "anomaly_score",
    "alert",
    "flow_duration_us",
    "protocol",
    "destination_port",
    "status",
    "reason",
]


def available_interfaces() -> list[dict[str, str]]:
    """Return interface labels and capture names without printing IP addresses."""
    try:
        from scapy.arch.windows import get_windows_if_list

        records = get_windows_if_list()
        return [
            {
                "name": str(item.get("name", "")),
                "description": str(item.get("description", "")),
                "capture_name": rf"\Device\NPF_{item.get('guid', '').strip('{}')}",
            }
            for item in records
        ]
    except (ImportError, OSError):
        try:
            from scapy.all import get_if_list

            return [{"name": str(name), "description": "", "capture_name": str(name)} for name in get_if_list()]
        except Exception as exc:  # Scapy reports platform/provider errors here.
            raise RuntimeError(f"Could not list capture interfaces: {exc}") from exc


def _canonical_features(vector: dict, feature_names: list[str]) -> dict:
    """Map extractor feature-vector spellings to CICFlowMeter CSV spellings."""
    try:
        from pycicflowmeter.writer import KEY_ALIASES
    except ImportError as exc:
        raise RuntimeError("Install the pinned live capture dependency from requirements-live.txt") from exc

    row = {}
    missing = []
    for name in feature_names:
        key = KEY_ALIASES.get(name, name)
        if name == "Destination Port" and key not in vector:
            key = "Dst Port"
        if key not in vector:
            missing.append(name)
        else:
            row[name] = vector[key]
    if missing:
        raise ValueError(f"flow extractor did not provide {len(missing)} trained features: {missing[:6]}")
    return row


class AlertWriter:
    """Append privacy-minimized scored flow events to a local CSV."""

    def __init__(self, output: Path, bundle: dict):
        self.output = output
        self.output.parent.mkdir(parents=True, exist_ok=True)
        self.bundle = bundle
        self.count = 0
        self.alert_count = 0
        self.failure_count = 0
        self.output.write_text(",".join(OUTPUT_COLUMNS) + "\n", encoding="utf-8")

    def __call__(self, flow_key: str, last_seen_us: int, vector: dict) -> None:
        try:
            features = _canonical_features(vector, self.bundle["feature_names"])
            frame = pd.DataFrame([features])
            scored = score_frame(frame, self.bundle).iloc[0]
            row = {
                "observed_at_utc": datetime.fromtimestamp(last_seen_us / 1e6, tz=timezone.utc).isoformat(),
                "model": self.bundle["model"],
                "anomaly_score": float(scored["anomaly_score"]),
                "alert": bool(scored["alert"]),
                "flow_duration_us": _safe_float(vector.get("Flow Duration")),
                "protocol": _safe_int(vector.get("Protocol")),
                "destination_port": _safe_int(vector.get("Dst Port")),
                "status": "scored",
                "reason": "",
            }
            self.alert_count += int(row["alert"])
            self.count += 1
        except Exception as exc:
            self.failure_count += 1
            LOG.warning("Skipping a flow that could not be safely scored: %s", exc)
            row = {
                "observed_at_utc": datetime.fromtimestamp(last_seen_us / 1e6, tz=timezone.utc).isoformat(),
                "model": self.bundle.get("model", "unknown"),
                "anomaly_score": "",
                "alert": "",
                "flow_duration_us": _safe_float(vector.get("Flow Duration")),
                "protocol": _safe_int(vector.get("Protocol")),
                "destination_port": _safe_int(vector.get("Dst Port")),
                "status": "not_scored",
                "reason": str(exc),
            }
        with self.output.open("a", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=OUTPUT_COLUMNS)
            writer.writerow(row)
            stream.flush()
        if row["status"] == "scored":
            LOG.info("flow scored: alert=%s score=%.5f", row["alert"], row["anomaly_score"])


def _safe_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return ""


def _safe_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return ""


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Capture authorized traffic as flows and score each finalized flow.")
    parser.add_argument("--list-interfaces", action="store_true", help="show available interface names, then exit")
    parser.add_argument("--interface", help="interface name or Windows Npcap capture name")
    parser.add_argument("--model", default="models/replay.joblib", help="local benign-trained .joblib bundle")
    parser.add_argument("--output", default="data/live/scored_flows.csv", help="local output CSV; no IPs or raw packets")
    parser.add_argument("--flow-timeout", type=float, default=30.0, help="maximum flow age before scoring, seconds")
    parser.add_argument("--activity-timeout", type=float, default=5.0, help="idle time before flow finalization, seconds")
    parser.add_argument("--promisc", action="store_true", help="enable promiscuous mode; off by default")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    if args.list_interfaces:
        try:
            interfaces = available_interfaces()
        except RuntimeError as exc:
            parser.error(str(exc))
        for item in interfaces:
            print(f"{item['name']} | {item['description']} | {item['capture_name']}")
        if not interfaces:
            print("No interfaces found. Install the live-capture dependency and Windows capture driver.")
        return 0
    if not args.interface:
        parser.error("--interface is required unless --list-interfaces is used")
    if args.flow_timeout <= 0 or args.activity_timeout <= 0:
        parser.error("flow timeouts must be positive")

    model_path = Path(args.model)
    if not model_path.is_file():
        parser.error(f"model bundle not found: {model_path}")
    bundle = joblib.load(model_path)
    interfaces = available_interfaces()
    selected = next((i for i in interfaces if args.interface in {i["name"], i["capture_name"]}), None)
    capture_interface = selected["capture_name"] if selected else args.interface

    try:
        from pycicflowmeter import FlowMeter
    except ImportError:
        parser.error("Live flow extractor is missing. Run: python -m pip install -r requirements-live.txt")

    consent = input("Confirm you own this network or have written permission to monitor it. Type YES to continue: ").strip()
    if consent != "YES":
        print("Capture cancelled.")
        return 2

    writer = AlertWriter(Path(args.output), bundle)
    meter = FlowMeter(on_flow_finalized=writer)
    meter.analyzer.FLOW_TIMEOUT = int(args.flow_timeout * 1_000_000)
    meter.analyzer.FLOW_ACTIVITY_TIMEOUT = int(args.activity_timeout * 1_000_000)
    meter.analyzer.cleanup_interval = min(5_000_000, int(args.flow_timeout * 1_000_000))
    LOG.info("Starting flow capture on %s; model=%s; output=%s", capture_interface, bundle["model"], args.output)
    LOG.info("Press Ctrl+C to stop. Flows are scored when finalized; some alerts can be delayed by the flow timeout.")
    try:
        meter.start_live(capture_interface, promisc=args.promisc)
    except KeyboardInterrupt:
        LOG.info("Capture stopped by operator.")
    except Exception as exc:
        LOG.error("Capture stopped: %s", exc)
        return 1
    finally:
        LOG.info("Final totals: scored=%d alerts=%d unscored=%d output=%s",
                 writer.count, writer.alert_count, writer.failure_count, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
