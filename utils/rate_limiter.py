# utils/rate_limiter.py

from datetime import datetime, timezone, timedelta

rate_limiter = {}

def check_rate_limit(ip: str, limit: int, window: timedelta):

    current_time = datetime.now(timezone.utc)

    # Create IP bucket
    if ip not in rate_limiter:
        rate_limiter[ip] = []

    # Remove expired timestamps
    rate_limiter[ip] = [
        timestamp
        for timestamp in rate_limiter[ip]
        if current_time - timestamp < window
    ]

    # Remove empty IPs (optional cleanup)
    if len(rate_limiter[ip]) == 0:
        rate_limiter.pop(ip, None)
        rate_limiter[ip] = []

    # Rate limit exceeded
    if len(rate_limiter[ip]) >= limit:
        return False

    # Store current request timestamp
    rate_limiter[ip].append(current_time)

    return True