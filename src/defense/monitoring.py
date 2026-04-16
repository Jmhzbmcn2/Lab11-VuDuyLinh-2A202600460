"""
Assignment 11 — Monitoring & Alerts
Muc dich: Theo doi metrics va kich hoat canh bao khi nguong bi vuot.
Tai sao can: Phat hien tan cong som, trace lo, va bao cao health cua he thong.
"""
import time
from dataclasses import dataclass, field
from typing import Callable, Optional
from collections import defaultdict
from datetime import datetime, timedelta


@dataclass
class Alert:
    """Mot canh bao khi nguong bi vuot."""
    name: str
    level: str  # "INFO" | "WARNING" | "CRITICAL"
    message: str
    timestamp: str
    value: float
    threshold: float


class MonitoringAlerts:
    """Monitoring & alerts cho defense pipeline.

    Theo doi cac metrics quan trong va kich hoat alert khi nguong bi vuot.
    Su dung sliding window de tinh toan metrics chinh xac.

    Args:
        window_seconds: Do dai cua so thoi gian de tinh metrics
    """

    # Nguong mac dinh
    DEFAULT_THRESHOLDS = {
        "block_rate": 0.3,        # 30% requests bi block -> canh bao
        "rate_limit_rate": 0.2,   # 20% requests bi rate limit -> canh bao
        "judge_fail_rate": 0.15,  # 15% judge fail -> canh bao
        "avg_latency_ms": 5000,    # 5s latency -> canh bao
        "blocked_per_minute": 10,  # 10 blocks/minute -> canh bao
    }

    def __init__(self, window_seconds: int = 300):
        self.window_seconds = window_seconds
        self.thresholds: dict[str, float] = dict(self.DEFAULT_THRESHOLDS)

        # Sliding window data
        self.events: list[dict] = []
        self.alerts: list[Alert] = []
        self.alert_callbacks: list[Callable[[Alert], None]] = []

        # Snapshot counters (for cumulative stats)
        self._total_requests = 0
        self._total_blocks = 0
        self._total_rate_limits = 0
        self._total_judge_fails = 0

    def record_event(
        self,
        event_type: str,
        blocked: bool = False,
        rate_limited: bool = False,
        judge_passed: bool = True,
        latency_ms: float = 0.0,
        layer: str = None,
    ):
        """Ghi mot event de tinh metrics.

        Args:
            event_type: "request" | "block" | "judge"
            blocked: Co bi block khong
            rate_limited: Co bi rate limit khong
            judge_passed: Judge co pass khong
            latency_ms: Do tre cua request
            layer: Layer nao block (neu co)
        """
        self._total_requests += 1

        event = {
            "timestamp": time.time(),
            "type": event_type,
            "blocked": blocked,
            "rate_limited": rate_limited,
            "judge_passed": judge_passed,
            "latency_ms": latency_ms,
            "layer": layer,
        }
        self.events.append(event)

        # Cleanup cu
        cutoff = time.time() - self.window_seconds
        self.events = [e for e in self.events if e["timestamp"] > cutoff]

        # Check alerts
        self._check_alerts()

    def register_alert_callback(self, callback: Callable[[Alert], None]):
        """Dang ky callback duoc goi khi co alert.

        Args:
            callback: Ham nhan tham so la Alert object
        """
        self.alert_callbacks.append(callback)

    def set_threshold(self, metric: str, value: float):
        """Dat nguong cho metric.

        Args:
            metric: Ten metric (xem DEFAULT_THRESHOLDS)
            value: Gia tri nguong
        """
        self.thresholds[metric] = value

    def _check_alerts(self):
        """Kiem tra va tao alert neu can."""
        metrics = self.get_metrics()

        # Block rate alert
        if metrics["block_rate"] > self.thresholds["block_rate"]:
            self._fire_alert(
                "BLOCK_RATE",
                "WARNING",
                f"Block rate {metrics['block_rate']:.1%} exceeds {self.thresholds['block_rate']:.1%}",
                metrics["block_rate"],
                self.thresholds["block_rate"],
            )

        # Rate limit alert
        if metrics["rate_limit_rate"] > self.thresholds["rate_limit_rate"]:
            self._fire_alert(
                "RATE_LIMIT",
                "WARNING",
                f"Rate limit rate {metrics['rate_limit_rate']:.1%} exceeds {self.thresholds['rate_limit_rate']:.1%}",
                metrics["rate_limit_rate"],
                self.thresholds["rate_limit_rate"],
            )

        # Judge fail rate alert
        if metrics["judge_fail_rate"] > self.thresholds["judge_fail_rate"]:
            self._fire_alert(
                "JUDGE_FAIL",
                "WARNING",
                f"Judge fail rate {metrics['judge_fail_rate']:.1%} exceeds {self.thresholds['judge_fail_rate']:.1%}",
                metrics["judge_fail_rate"],
                self.thresholds["judge_fail_rate"],
            )

        # Latency alert
        if metrics["avg_latency_ms"] > self.thresholds["avg_latency_ms"]:
            self._fire_alert(
                "LATENCY",
                "WARNING",
                f"Avg latency {metrics['avg_latency_ms']:.0f}ms exceeds {self.thresholds['avg_latency_ms']:.0f}ms",
                metrics["avg_latency_ms"],
                self.thresholds["avg_latency_ms"],
            )

    def _fire_alert(self, name: str, level: str, message: str, value: float, threshold: float):
        """Tao va fire alert."""
        # Tranh duplicate alert lien tiep
        recent = [a for a in self.alerts[-3:] if a.name == name]
        if recent and (time.time() - self._parse_timestamp(recent[-1].timestamp)) < 60:
            return

        alert = Alert(
            name=name,
            level=level,
            message=message,
            timestamp=datetime.now().isoformat(),
            value=value,
            threshold=threshold,
        )
        self.alerts.append(alert)
        print(f"\n[ALERT {level}] {name}: {message}")

        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                print(f"Alert callback error: {e}")

    def _parse_timestamp(self, ts: str) -> float:
        """Parse ISO timestamp to epoch."""
        try:
            return datetime.fromisoformat(ts).timestamp()
        except Exception:
            return time.time()

    def get_metrics(self) -> dict:
        """Lay metrics hien tai trong sliding window.

        Returns:
            Dict voi cac metrics da tinh
        """
        if not self.events:
            return {
                "total_requests": 0,
                "blocked": 0,
                "rate_limited": 0,
                "judge_fails": 0,
                "block_rate": 0.0,
                "rate_limit_rate": 0.0,
                "judge_fail_rate": 0.0,
                "avg_latency_ms": 0.0,
                "requests_per_minute": 0.0,
            }

        total = len(self.events)
        blocked = sum(1 for e in self.events if e.get("blocked"))
        rate_limited = sum(1 for e in self.events if e.get("rate_limited"))
        judge_fails = sum(1 for e in self.events if not e.get("judge_passed", True))
        latencies = [e.get("latency_ms", 0) for e in self.events if e.get("latency_ms")]
        avg_latency = sum(latencies) / len(latencies) if latencies else 0.0

        # Requests per minute
        window_min = self.window_seconds / 60.0
        rpm = total / max(0.1, window_min)

        return {
            "total_requests": total,
            "blocked": blocked,
            "rate_limited": rate_limited,
            "judge_fails": judge_fails,
            "block_rate": blocked / max(1, total),
            "rate_limit_rate": rate_limited / max(1, total),
            "judge_fail_rate": judge_fails / max(1, total),
            "avg_latency_ms": avg_latency,
            "requests_per_minute": rpm,
        }

    def print_metrics(self):
        """In ra metrics hien tai."""
        m = self.get_metrics()
        print("\n" + "=" * 60)
        print("DEFENSE PIPELINE METRICS")
        print("=" * 60)
        print(f"  Total requests:       {m['total_requests']}")
        print(f"  Blocked:              {m['blocked']} ({m['block_rate']:.1%})")
        print(f"  Rate limited:         {m['rate_limited']} ({m['rate_limit_rate']:.1%})")
        print(f"  Judge fails:          {m['judge_fails']} ({m['judge_fail_rate']:.1%})")
        print(f"  Avg latency:          {m['avg_latency_ms']:.0f}ms")
        print(f"  Requests/minute:      {m['requests_per_minute']:.1f}")
        print("=" * 60)

    def print_alerts(self):
        """In ra cac alert gan nhat."""
        if not self.alerts:
            print("No alerts fired.")
            return

        print("\n" + "=" * 60)
        print(f"ALERTS ({len(self.alerts)} total)")
        print("=" * 60)
        for alert in self.alerts[-10:]:  # Chi hien thi 10 alert gan nhat
            print(f"  [{alert.level}] {alert.timestamp} - {alert.name}")
            print(f"           {alert.message}")
        print("=" * 60)
