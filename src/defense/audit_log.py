"""
Assignment 11 — Audit Log
Mục đích: Ghi lại mọi tương tác để phục vụ compliance, debugging, và forensic analysis.
Tại sao cần: Không có audit log, ta không thể biết điều gì đã xảy ra khi có sự cố bảo mật.
"""
import json
import threading
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class AuditEntry:
    """Một bản ghi audit cho một request.

    Lưu đầy đủ thông tin để có thể reproduce và investigate
    bất kỳ incident nào.
    """
    timestamp: str
    user_id: str
    request_id: str
    input_text: str
    response_text: str
    blocked_layer: Optional[str]  # None = passed all layers
    block_reason: Optional[str]
    latency_ms: float
    judge_scores: dict = field(default_factory=dict)
    rate_limited: bool = False
    wait_time_seconds: float = 0.0


class AuditLogger:
    """Audit logger cho defense pipeline.

    Thread-safe, ghi log vào memory và export được sang JSON.
    Mỗi request tạo một AuditEntry chứa đầy đủ ngữ cảnh.

    Args:
        max_entries: Số entry tối đa giữ trong memory (None = unlimited)
    """

    def __init__(self, max_entries: int = None):
        self.entries: list[AuditEntry] = []
        self.max_entries = max_entries
        self.lock = threading.Lock()
        self._request_counter = 0
        self._request_lock = threading.Lock()

    def _next_request_id(self) -> str:
        """Tạo request ID duy nhất."""
        with self._request_lock:
            self._request_counter += 1
            return f"req_{self._request_counter:06d}"

    def log_request_start(
        self,
        user_id: str,
        input_text: str,
        rate_limited: bool = False,
        wait_time: float = 0.0,
    ) -> str:
        """Ghi log khi request bắt đầu (sau khi qua rate limiter).

        Args:
            user_id: ID của user
            input_text: Nội dung message
            rate_limited: Có bị rate limit không
            wait_time: Thời gian chờ (nếu bị rate limit)

        Returns:
            request_id để tracking
        """
        request_id = self._next_request_id()
        entry = AuditEntry(
            timestamp=datetime.now().isoformat(),
            user_id=user_id,
            request_id=request_id,
            input_text=input_text[:500] if input_text else "",
            response_text="",
            blocked_layer="rate_limiter" if rate_limited else None,
            block_reason=f"Rate limit exceeded. Wait {wait_time:.1f}s" if rate_limited else None,
            latency_ms=0.0,
            rate_limited=rate_limited,
            wait_time_seconds=wait_time,
        )
        with self.lock:
            self.entries.append(entry)
            if self.max_entries and len(self.entries) > self.max_entries:
                self.entries = self.entries[-self.max_entries:]
        return request_id

    def log_response(
        self,
        request_id: str,
        response_text: str,
        blocked_layer: Optional[str] = None,
        block_reason: Optional[str] = None,
        latency_ms: float = 0.0,
        judge_scores: dict = None,
    ):
        """Cập nhật audit entry với response.

        Args:
            request_id: ID từ log_request_start
            response_text: Response của agent
            blocked_layer: Layer nào đã block (-1 = input guardrail, "output" = output guardrail)
            block_reason: Lý do block
            latency_ms: Thời gian xử lý
            judge_scores: Điểm số từ LLM-as-Judge
        """
        with self.lock:
            for entry in reversed(self.entries):
                if entry.request_id == request_id:
                    entry.response_text = response_text[:1000] if response_text else ""
                    entry.blocked_layer = blocked_layer
                    entry.block_reason = block_reason
                    entry.latency_ms = latency_ms
                    if judge_scores:
                        entry.judge_scores = judge_scores
                    break

    def log_block(
        self,
        request_id: str,
        layer: str,
        reason: str,
        response_text: str = "",
    ):
        """Ghi log khi một layer block request.

        Args:
            request_id: ID từ log_request_start
            layer: Tên layer đã block (e.g., "input_guardrail", "output_guardrail")
            reason: Lý do block chi tiết
            response_text: Response thay thế
        """
        with self.lock:
            for entry in reversed(self.entries):
                if entry.request_id == request_id:
                    entry.blocked_layer = layer
                    entry.block_reason = reason
                    entry.response_text = response_text[:1000] if response_text else ""
                    break

    def get_recent(self, n: int = 10) -> list[AuditEntry]:
        """Lấy n entries gần nhất."""
        with self.lock:
            return list(self.entries[-n:])

    def get_blocked_entries(self) -> list[AuditEntry]:
        """Lấy tất cả entries bị block."""
        with self.lock:
            return [e for e in self.entries if e.blocked_layer is not None]

    def get_stats(self) -> dict:
        """Tính thống kê từ audit log."""
        with self.lock:
            total = len(self.entries)
            if total == 0:
                return {"total": 0, "blocked": 0, "passed": 0, "block_rate": 0.0}
            blocked = sum(1 for e in self.entries if e.blocked_layer is not None)
            return {
                "total": total,
                "blocked": blocked,
                "passed": total - blocked,
                "block_rate": blocked / total,
                "total_entries": total,
            }

    def export_json(self, filepath: str = "audit_log.json"):
        """Export to JSON file for forensic analysis.

        Args:
            filepath: Đường dẫn file output
        """
        with self.lock:
            data = [asdict(e) for e in self.entries]
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        print(f"Exported {len(data)} audit entries to {filepath}")
