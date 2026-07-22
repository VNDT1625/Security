#!/usr/bin/env python3
"""Small, bounded HTTP load probe for Prewise release verification.

This is intentionally not a stress-test or DDoS tool.  It caps concurrency and
request count, requires an explicit flag for public targets, and reports enough
latency/status information to compare releases on the same environment.
"""

from __future__ import annotations

import argparse
import asyncio
import math
import statistics
import time
from collections import Counter
from urllib.parse import urlsplit

import httpx


MAX_REQUESTS = 500
MAX_CONCURRENCY = 25
LOCAL_HOSTS = {"127.0.0.1", "::1", "localhost"}


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, math.ceil(fraction * len(ordered)) - 1))
    return ordered[index]


async def run_probe(url: str, requests: int, concurrency: int, timeout: float) -> int:
    semaphore = asyncio.Semaphore(concurrency)
    latencies_ms: list[float] = []
    statuses: Counter[str] = Counter()

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout),
        follow_redirects=False,
        headers={"User-Agent": "Prewise-Release-Load-Probe/1.0"},
    ) as client:

        async def one_request() -> None:
            async with semaphore:
                started = time.perf_counter()
                try:
                    response = await client.get(url)
                    statuses[str(response.status_code)] += 1
                except httpx.TimeoutException:
                    statuses["timeout"] += 1
                except httpx.HTTPError:
                    statuses["network_error"] += 1
                finally:
                    latencies_ms.append((time.perf_counter() - started) * 1000)

        wall_started = time.perf_counter()
        await asyncio.gather(*(one_request() for _ in range(requests)))
        wall_seconds = time.perf_counter() - wall_started

    successful = sum(count for status, count in statuses.items() if status.startswith("2"))
    print(f"target={url}")
    print(f"requests={requests} concurrency={concurrency} wall_seconds={wall_seconds:.3f}")
    print(f"throughput_rps={requests / wall_seconds:.2f}")
    print(f"status_counts={dict(sorted(statuses.items()))}")
    print(
        "latency_ms="
        f"min:{min(latencies_ms):.2f} "
        f"mean:{statistics.fmean(latencies_ms):.2f} "
        f"p50:{percentile(latencies_ms, 0.50):.2f} "
        f"p95:{percentile(latencies_ms, 0.95):.2f} "
        f"p99:{percentile(latencies_ms, 0.99):.2f} "
        f"max:{max(latencies_ms):.2f}"
    )
    return 0 if successful == requests else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url")
    parser.add_argument("--requests", type=int, default=100)
    parser.add_argument("--concurrency", type=int, default=10)
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument(
        "--allow-public",
        action="store_true",
        help="Acknowledge that the target is not loopback/local development.",
    )
    args = parser.parse_args()
    if not 1 <= args.requests <= MAX_REQUESTS:
        parser.error(f"--requests must be between 1 and {MAX_REQUESTS}")
    if not 1 <= args.concurrency <= min(MAX_CONCURRENCY, args.requests):
        parser.error(
            f"--concurrency must be between 1 and {min(MAX_CONCURRENCY, args.requests)}"
        )
    if not 0.5 <= args.timeout <= 60:
        parser.error("--timeout must be between 0.5 and 60 seconds")
    hostname = (urlsplit(args.url).hostname or "").lower()
    if hostname not in LOCAL_HOSTS and not args.allow_public:
        parser.error("public targets require --allow-public")
    return args


def main() -> int:
    args = parse_args()
    return asyncio.run(
        run_probe(args.url, args.requests, args.concurrency, args.timeout)
    )


if __name__ == "__main__":
    raise SystemExit(main())
