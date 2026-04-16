"""
Assignment 11 — Rate Limiter
Mục đích: Ngăn chặn abuse bằng cách giới hạn số request trên mỗi user trong một khoảng thời gian.
Tại sao cần: Không có rate limit, attacker có thể brute-force thử hàng ngàn prompt injection trong giây lát.
"""
from collections import defaultdict, deque
import time
import threading


class RateLimiter:
    """Sliding-window rate limiter per user.

    Args:
        max_requests: Số request tối đa được phép trong window
        window_seconds: Độ dài window (giây)

    Giải thuật:
        1. Dùng deque lưu timestamp của mỗi request
        2. Khi có request mới, xóa các timestamp cũ hơn window_seconds
        3. Nếu deque chưa đầy -> cho phép, thêm timestamp
        4. Nếu deque đầy -> block, tính thời gian chờ
    """

    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.user_windows = defaultdict(deque)
        self.lock = threading.Lock()
        self.total_requests = 0
        self.blocked_requests = 0

    def check(self, user_id: str = "anonymous") -> tuple[bool, float]:
        """Kiểm tra xem user có được phép gửi request không.

        Args:
            user_id: ID của user

        Returns:
            Tuple (allowed, wait_seconds)
            - allowed: True nếu được phép, False nếu bị block
            - wait_seconds: Số giây cần chờ nếu bị block
        """
        now = time.time()

        with self.lock:
            window = self.user_windows[user_id]

            while window and now - window[0] > self.window_seconds:
                window.popleft()

            self.total_requests += 1

            if len(window) >= self.max_requests:
                self.blocked_requests += 1
                oldest = window[0]
                wait = self.window_seconds - (now - oldest)
                return False, max(0.0, wait)

            window.append(now)
            return True, 0.0

    def get_remaining(self, user_id: str = "anonymous") -> int:
        """Số request còn lại cho user trong window hiện tại."""
        with self.lock:
            window = self.user_windows.get(user_id, deque())
            now = time.time()
            valid = [t for t in window if now - t <= self.window_seconds]
            return max(0, self.max_requests - len(valid))

    def reset(self, user_id: str = "anonymous"):
        """Reset counter cho user."""
        with self.lock:
            if user_id in self.user_windows:
                del self.user_windows[user_id]

    def get_stats(self) -> dict:
        """Trả về thống kê rate limiter."""
        return {
            "total_requests": self.total_requests,
            "blocked_requests": self.blocked_requests,
            "block_rate": self.blocked_requests / max(1, self.total_requests),
        }
