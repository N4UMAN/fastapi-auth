import asyncio
import math
from redis.exceptions import NoScriptError

from fastapi import HTTPException, status
import redis.asyncio as async_redis
# from rq import Queue  # TODO: wire up email queue
from app.core.config import settings
from app.core.logger import logger


class RedisManager():
    def __init__(self):
        self.async_client: async_redis.Redis | None = None
        self.rate_limit_sha: str | None = None

        self._RATE_LIMIT_SCRIPT = """
                    local ip_key = KEYS[1]
                    local device_key = KEYS[2]

                    local max_req_per_ip = tonumber(ARGV[1])
                    local max_req_per_dev = tonumber(ARGV[2])
                    local ttl = tonumber(ARGV[3])


                    local ip_count = redis.call("INCR", ip_key)
                    if ip_count == 1 then
                        redis.call("EXPIRE", ip_key, ttl)
                    end

                    local device_count = redis.call("INCR", device_key)
                    if device_count == 1 then
                        redis.call("EXPIRE", device_key, ttl)
                    end


                    if ip_count > max_req_per_ip then
                        redis.call("DECR", ip_key)
                        return {0, "Too many requests from this IP"}
                    end

                    if device_count > max_req_per_dev  then
                        redis.call("DECR", device_key)
                        return {0, "Too many requests from this device"}
                    end

                    return {1, "Allowed"}
"""

    async def init(self):
        """
        Initializes async and sync Redis clients and preloads the rate limit Lua script.
        Lua script is loaded once via script_load and referenced by SHA for efficiency.
        """
        MAX_RETRIES = settings.REDIS_MAX_RETRIES

        for attempt in range(1, MAX_RETRIES+1):
            try:
                self.async_client = async_redis.from_url(
                    settings.redis_url,
                    decode_responses=True
                )
                self.rate_limit_sha = await self.async_client.script_load(self._RATE_LIMIT_SCRIPT)

                logger.info("Redis client online")
                return

            except Exception as e:
                logger.warning(f"Redis init failed ({attempt}/{MAX_RETRIES}): {e}")
                if attempt < MAX_RETRIES:
                    await asyncio.sleep(2**attempt)

        raise RuntimeError("Redis failed to initialize after maximum retries")

    async def check_signup_limit(self, ip_key: str, device_key: str) -> tuple[bool, str]:
        """
        Runs rate limit check against IP and device keys.
        Returns (True, "Allowed") or (False, reason) from the Lua script.
        """
        MAX_RETRIES = settings.REDIS_MAX_RETRIES

        config = settings.signup_rate_limit_config
        for attempt in range(1, MAX_RETRIES):
            try:
                result = await self.async_client.evalsha(
                    self.rate_limit_sha,
                    2,
                    ip_key, device_key,
                    config["ip_limit"], config["device_limit"], config["window"]
                )

                allowed, reason = bool(int(result[0])), result[1]

                return (allowed, reason)

            except NoScriptError:
                logger.warning("Lua script missing from Redis, reloading...")
                self.rate_limit_sha = await self.async_client.script_load(self._RATE_LIMIT_SCRIPT)

            except Exception as e:
                logger.error(f"Redis evalsha failed (attempt {attempt}/{MAX_RETRIES}): {e}")
                if attempt < MAX_RETRIES:
                    await asyncio.sleep(2 ** attempt)

        raise RuntimeError("Redis rate limit check failed after maximum retries")

    async def check_login_rate(self, ip_key: str, user_key: str) -> tuple[bool, str]:
        """
        Checks both ban status and rate limits for IP and user keys.
        """

        for key in [ip_key, user_key]:
            banned, ttl = await self._is_login_blocked(key)
            if banned:
                return True, self._format_ttl(ttl)

        blocked, ttl_str = await self._check_login_limit(ip_key, user_key)

        return blocked, ttl_str

    async def roll_back_signup_counter(self, ip_key, device_key):
        """
        Decrements IP and device counters on signup failure.
        Prevents counting requests that didn't complete successfully.
        """

        await self.async_client.decr(ip_key)
        await self.async_client.decr(device_key)

    async def reset_login_failures(self, ip_key: str, user_key: str):
        await self.async_client.delete(f"fail:{ip_key}", f"fail:{user_key}")
        await self.async_client.delete(f"ban:{ip_key}", f"ban:{user_key}")

    # ----Helpers----
    async def _increment_login_counter_with_ttl(self, key: str, window: int = settings.LOGIN_WINDOW) -> int:
        """
        Increments IP counters on signup failure.
        """
        count = await self.async_client.incr(key)

        if count == 1:
            await self.async_client.expire(key, window)

        return count

    async def _is_login_blocked(self, key: str) -> tuple[bool, int]:
        """
        Checks if a key is currently banned.
        Returns (True, remaining_ttl_seconds) if banned, (False, 0) otherwise.
        """
        ttl = await self.async_client.ttl(f"ban:{key}")

        if ttl and ttl > 0:
            return True, ttl

        return False, 0

    async def _check_login_limit(self, ip_key: str, user_key: str) -> tuple[bool, str]:
        """
        Checks login rate limits for both IP and user keys.
        """
        for key, limit in [(ip_key, settings.LOGIN_LIMIT_IP), (user_key, settings.LOGIN_LIMIT_USER)]:
            if await self._increment_login_counter_with_ttl(key) > limit:

                ttl = await self.async_client.ttl(key)
                return True, self._format_ttl(ttl)

        return False, 0

    async def _apply_failed_login_penalty(self, ip_key: str, user_key: str) -> None:
        """
        Increments the failure counter for a key.
        On first failure, sets a 24h expiry on the counter.
        After {MAX_LOGIN_ATTEMPTS} failures, calculates exponential backoff and sets a ban key.
        """
        for key in [ip_key, user_key]:
            fail_count = await self.async_client.incr(f"fail:{key}")

        if fail_count == 1:
            await self.async_client.expire(f"fail:{key}", 24 * 60 * 60)

        if fail_count > settings.MAX_LOGIN_ATTEMPTS:
            delay = self._calculate_backoff_time(fail_count)
            await self.async_client.setex(f"ban:{key}", delay, 1)

    async def close(self):
        if self.async_client:
            await self.async_client.close()

    @staticmethod
    def _calculate_backoff_time(failure_count: int) -> int:
        """
        Exponential backoff: BASE * 2^(n-1), capped at BACKOFF_TIME_MAX.
        failure 4 = BASE * 8
        failure 5 = BASE * 16
        ... capped at MAX
        """
        delay = settings.BACKOFF_TIME_BASE * (2**(failure_count - 1))
        return min(delay, settings.BACKOFF_TIME_MAX)

    @staticmethod
    def _format_ttl(ttl: int) -> str:
        """Converts a TTL in seconds to a human-readable string (e.g. '5 min', '2 hrs')."""
        if ttl < 60:
            return f"{ttl}s"
        elif ttl < 3600:
            return f"{math.ceil(ttl / 60)} mins"
        else:
            return f"{math.ceil(ttl / 3600)} hrs"


redis_mgr = RedisManager()
