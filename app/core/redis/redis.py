from redis import Redis
import redis.asyncio as async_redis
# from rq import Queue  # TODO: wire up email queue
from app.core.config import settings


class RedisManager():
    def __init__(self):
        self.async_client: async_redis.Redis | None = None
        self.sync_client: Redis | None = None
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

        self.async_client = async_redis.from_url(
            settings.redis_url,
            decode_responses=True
        )
        self.rate_limit_sha = await self.async_client.script_load(self._RATE_LIMIT_SCRIPT)

        self.sync_client = Redis.from_url(settings.redis_url)

    async def check_signup_limit(self, ip_key: str, device_key: str) -> tuple[bool, str]:
        """
        Runs rate limit check against IP and device keys.
        Returns (True, "Allowed") or (False, reason) from the Lua script.
        """

        config = settings.signup_rate_limit_config

        result = await self.async_client.evalsha(
            self.rate_limit_sha,
            2,
            ip_key, device_key,
            config["ip_limit"], config["device_limit"], config["window"]
        )

        allowed, reason = bool(int(result[0])), result[1]

        return (allowed, reason)

    async def roll_back_signup_counter(self, ip_key, device_key):
        """
        Decrements IP and device counters on signup failure.
        Prevents counting requests that didn't complete successfully.
        """

        self.async_client.decr(ip_key)
        self.async_client.decr(device_key)

    async def close(self):
        if self.async_client:
            await self.async_client.close()


redis_mgr = RedisManager()
