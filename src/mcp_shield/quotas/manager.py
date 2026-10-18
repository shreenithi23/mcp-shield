"""Layer 3: Quotas and Circuit Breaker tracking calls/min, writes/hour, records/day."""

import time
from typing import Optional, Tuple
from mcp_shield.database import ephemeral_cache


class QuotaAndCircuitBreakerManager:
    """Manages rate limiting, quotas, and denial-triggered circuit breaking."""

    def __init__(
        self,
        calls_per_min: int = 60,
        writes_per_hour: int = 100,
        records_per_day: int = 5000,
        circuit_breaker_denial_threshold: int = 5,
        circuit_breaker_cooldown_seconds: int = 60,
    ):
        self.calls_per_min = calls_per_min
        self.writes_per_hour = writes_per_hour
        self.records_per_day = records_per_day
        self.denial_threshold = circuit_breaker_denial_threshold
        self.cooldown_seconds = circuit_breaker_cooldown_seconds

    async def check(
        self,
        client_id: str,
        user_id: Optional[str],
        tool: str,
        is_write: bool = False,
        record_count: int = 1,
    ) -> Tuple[bool, Optional[str], Optional[int]]:
        """Checks circuit breaker state and rate quotas.
        
        Returns:
            (allowed: bool, reason: Optional[str], retry_after: Optional[int])
        """
        now = int(time.time())
        subject = f"{client_id}:{user_id or 'anon'}:{tool}"

        # 1. Check Circuit Breaker
        cb_trip_key = f"cb:tripped:{client_id}"
        tripped_expiry = await ephemeral_cache.get(cb_trip_key)
        if tripped_expiry:
            remaining = int(tripped_expiry) - now
            if remaining > 0:
                return False, "circuit_breaker_open: repeated policy denials triggered cooldown", remaining
            else:
                await ephemeral_cache.delete(cb_trip_key)

        # 2. Check Calls per Minute (Window: 60s)
        min_key = f"quota:cpm:{subject}:{now // 60}"
        curr_calls = int(await ephemeral_cache.get(min_key) or 0)
        if curr_calls >= self.calls_per_min:
            retry_after = 60 - (now % 60)
            return False, f"quota_exceeded: calls/min limit of {self.calls_per_min} reached", retry_after

        # 3. Check Writes per Hour (Window: 3600s)
        if is_write:
            hr_key = f"quota:wph:{subject}:{now // 3600}"
            curr_writes = int(await ephemeral_cache.get(hr_key) or 0)
            if curr_writes >= self.writes_per_hour:
                retry_after = 3600 - (now % 3600)
                return False, f"quota_exceeded: writes/hour limit of {self.writes_per_hour} reached", retry_after

        # 4. Check Records per Day (Window: 86400s)
        day_key = f"quota:rpd:{subject}:{now // 86400}"
        curr_records = int(await ephemeral_cache.get(day_key) or 0)
        if curr_records + record_count > self.records_per_day:
            retry_after = 86400 - (now % 86400)
            return False, f"quota_exceeded: records/day limit of {self.records_per_day} reached", retry_after

        # Increment quotas
        await ephemeral_cache.set(min_key, str(curr_calls + 1), ex=120)
        if is_write:
            await ephemeral_cache.set(hr_key, str(curr_writes + 1), ex=7200)
        await ephemeral_cache.set(day_key, str(curr_records + record_count), ex=172800)

        return True, None, None

    async def record_denial(self, client_id: str) -> bool:
        """Records a policy denial. If threshold is reached, trips the circuit breaker."""
        now = int(time.time())
        denial_key = f"cb:denials:{client_id}"
        count = int(await ephemeral_cache.get(denial_key) or 0) + 1
        await ephemeral_cache.set(denial_key, str(count), ex=self.cooldown_seconds)

        if count >= self.denial_threshold:
            # Trip circuit breaker
            trip_until = now + self.cooldown_seconds
            await ephemeral_cache.set(f"cb:tripped:{client_id}", str(trip_until), ex=self.cooldown_seconds)
            return True
        return False

    async def record_success(self, client_id: str) -> None:
        """Resets consecutive denial counter on legitimate allowed request."""
        await ephemeral_cache.delete(f"cb:denials:{client_id}")


quota_manager = QuotaAndCircuitBreakerManager()
