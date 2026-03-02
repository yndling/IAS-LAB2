"""Utility helpers used across the crypto package."""

import time


def benchmark(func, *args, iterations: int = 1000) -> float:
    """Simple timing helper.

    Executes ``func(*args)`` ``iterations`` times and returns the average
    duration in seconds.  This is sufficient for a rough performance
    comparison in the demonstration script; a real benchmark would want to
    do warm‑up passes, statistical analysis, etc.
    """

    start = time.perf_counter()
    for _ in range(iterations):
        func(*args)
    end = time.perf_counter()
    return (end - start) / iterations
