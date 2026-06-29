#!/usr/bin/env python3
"""
shared/retry.py

Exponential backoff retry decorator for transient failures.
Replaces bare `except Exception: pass` patterns across the codebase.
"""

import time
import logging
import functools
from typing import Tuple, Type

logger = logging.getLogger(__name__)


def retry(
    max_attempts: int = 3,
    backoff_base: float = 2.0,
    exceptions: Tuple[Type[BaseException], ...] = (Exception,),
    on_retry: str = "Retrying {func_name} (attempt {attempt}/{max_attempts}) after {error}"
):
    """
    Decorator that retries a function on specified exceptions with exponential backoff.
    
    Args:
        max_attempts: Maximum number of attempts (including the first).
        backoff_base: Base for exponential backoff (seconds). Delay = base^(attempt-1).
        exceptions: Tuple of exception types to catch and retry on.
        on_retry: Log message template. Supports {func_name}, {attempt}, {max_attempts}, {error}.
    
    Example:
        @retry(max_attempts=3, exceptions=(dns.resolver.Timeout, dns.resolver.NoAnswer))
        def resolve_dns(domain):
            return resolver.resolve(domain, 'A')
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_error = None
            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_error = e
                    if attempt < max_attempts:
                        delay = backoff_base ** (attempt - 1)
                        logger.warning(
                            on_retry.format(
                                func_name=func.__name__,
                                attempt=attempt,
                                max_attempts=max_attempts,
                                error=str(e)
                            )
                        )
                        time.sleep(delay)
                    else:
                        logger.error(
                            f"{func.__name__} failed after {max_attempts} attempts: {e}"
                        )
            raise last_error
        return wrapper
    return decorator


def retry_async(
    max_attempts: int = 3,
    backoff_base: float = 2.0,
    exceptions: Tuple[Type[BaseException], ...] = (Exception,),
    on_retry: str = "Retrying {func_name} (attempt {attempt}/{max_attempts}) after {error}"
):
    """Async version of the retry decorator."""
    import asyncio
    
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            last_error = None
            for attempt in range(1, max_attempts + 1):
                try:
                    return await func(*args, **kwargs)
                except exceptions as e:
                    last_error = e
                    if attempt < max_attempts:
                        delay = backoff_base ** (attempt - 1)
                        logger.warning(
                            on_retry.format(
                                func_name=func.__name__,
                                attempt=attempt,
                                max_attempts=max_attempts,
                                error=str(e)
                            )
                        )
                        await asyncio.sleep(delay)
                    else:
                        logger.error(
                            f"{func.__name__} failed after {max_attempts} attempts: {e}"
                        )
            raise last_error
        return wrapper
    return decorator
