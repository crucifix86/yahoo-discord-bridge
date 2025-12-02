"""
Utility functions for the Yahoo-Discord Bridge
"""

import asyncio
import logging
from typing import Callable, Optional

logger = logging.getLogger(__name__)


class ReconnectHandler:
    """
    Handles automatic reconnection with exponential backoff.
    """

    def __init__(self, max_retries: int = 10, base_delay: float = 1.0,
                 max_delay: float = 300.0):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.retry_count = 0
        self._running = False

    def reset(self):
        """Reset retry count after successful connection"""
        self.retry_count = 0

    def get_delay(self) -> float:
        """Calculate delay for next retry using exponential backoff"""
        delay = min(self.base_delay * (2 ** self.retry_count), self.max_delay)
        self.retry_count += 1
        return delay

    def should_retry(self) -> bool:
        """Check if we should attempt another retry"""
        return self.retry_count < self.max_retries

    async def run_with_reconnect(self, connect_func: Callable,
                                  on_connected: Optional[Callable] = None,
                                  on_disconnected: Optional[Callable] = None):
        """
        Run a connection function with automatic reconnection.

        Args:
            connect_func: Async function that establishes connection
            on_connected: Callback when connection is established
            on_disconnected: Callback when connection is lost
        """
        self._running = True

        while self._running and self.should_retry():
            try:
                logger.info("Attempting to connect...")
                await connect_func()

                # Connection successful
                self.reset()
                if on_connected:
                    await on_connected()

                # Wait for disconnect (connect_func should block while connected)

            except asyncio.CancelledError:
                logger.info("Connection cancelled")
                break
            except Exception as e:
                logger.error(f"Connection failed: {e}")

                if on_disconnected:
                    await on_disconnected()

                if self.should_retry():
                    delay = self.get_delay()
                    logger.info(f"Reconnecting in {delay:.1f}s (attempt {self.retry_count}/{self.max_retries})")
                    await asyncio.sleep(delay)
                else:
                    logger.error("Max retries reached, giving up")
                    break

    def stop(self):
        """Stop reconnection attempts"""
        self._running = False


class RateLimiter:
    """
    Simple rate limiter to avoid Discord rate limits.
    """

    def __init__(self, calls_per_second: float = 1.0):
        self.min_interval = 1.0 / calls_per_second
        self.last_call = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self):
        """Wait until we can make the next call"""
        async with self._lock:
            import time
            now = time.time()
            elapsed = now - self.last_call
            if elapsed < self.min_interval:
                await asyncio.sleep(self.min_interval - elapsed)
            self.last_call = time.time()


def sanitize_username(username: str) -> str:
    """
    Sanitize a username for YMSG protocol.
    Removes characters that might cause issues.
    """
    # Remove null bytes and control characters
    username = ''.join(c for c in username if ord(c) >= 32)
    # Limit length
    if len(username) > 32:
        username = username[:32]
    return username


def format_timestamp() -> str:
    """Get current timestamp in Yahoo Messenger format"""
    from datetime import datetime
    return datetime.now().strftime("%H:%M:%S")
