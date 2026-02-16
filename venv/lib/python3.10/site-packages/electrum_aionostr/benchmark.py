"""
Run these benchmarks like so:

aionostr bench -r ws://localhost:6969 -f events_per_second -c 2

Available benchmarks:
    events_per_second: measures reading events
    req_per_second: measures total time from subscribing, reading, to unsubscribing
    adds_per_second: measures time to add events
"""
import asyncio
import secrets
import traceback
from time import perf_counter, time

from aiohttp import ClientSession
import logging

from .event import Event
from .key import PrivateKey
from .relay import Relay, loads, dumps


class catchtime:
    __slots__ = ("start", "count", "duration")

    def __enter__(self):
        self.start = perf_counter()
        self.count = 0
        return self

    def __exit__(self, type, value, traceback):
        self.duration = perf_counter() - self.start

    def __add__(self, value):
        self.count += value
        return self

    def throughput(self):
        return self.count / self.duration


def make_events(num_events):
    private_key = PrivateKey()
    pubkey = private_key.public_key.hex()
    prikey = private_key.hex()
    events = []
    expiration = str(int(time()) + 1200)
    tags = [["t", "benchmark"], ["expiration", expiration]]
    for i in range(num_events):
        e = Event(kind=9999, content=secrets.token_hex(6), pubkey=pubkey, tags=tags)
        e = e.sign(prikey)
        events.append(e)
    return events


async def adds_per_second(url, num_events=100):
    events = make_events(num_events)
    async with ClientSession() as client:
        relay = Relay(url, client=client)
        async with relay:
            with catchtime() as timer:
                for e in events:
                    await relay.add_event(e, check_response=True)
                    timer += 1
    print(f"\tAdd: took {timer.duration:.2f} seconds. {timer.throughput():.1f}/sec")
    return timer.throughput()


async def events_per_second(url, kind=9999, limit=500, duration=20, id=None, **kwargs):
    query = {"kinds": [kind], "limit": limit}
    async with ClientSession() as client:
        async with client.ws_connect(url) as ws:
            print(f"connected {id}")
            timer, total_bytes = await asyncio.wait_for(_make_requests(ws, query, limit, duration), timeout=duration+1)

    bps = (total_bytes / timer.duration) / 1024
    print(
        f"\tEvents: took {timer.duration:.2f} seconds. {timer.throughput():.1f}/sec {bps:.1f}kBps"
    )
    return timer.count, total_bytes


async def _make_requests(ws, query, limit, duration):
    total_bytes = 0
    stoptime = perf_counter() + duration
    query_str = dumps(["REQ", "bench", query])
    query_close = dumps(["CLOSE", "bench"])
    send = ws.send_str
    recv = ws.receive_str
    with catchtime() as timer:
        while perf_counter() < stoptime:
            try:
                await send(query_str)
                count = 0
                while True:
                    event = await recv()
                    total_bytes += len(event)
                    if not event.startswith('["EVENT"'):
                        if count != limit:
                            raise Exception(f"Did not receive full req: {count} {limit}")
                        break
                    count += 1
                timer += 1
                await send(query_close)
            except asyncio.exceptions.CancelledError:
                break
            except asyncio.exceptions.TimeoutError:
                print(f"ERROR: task timed out while reading")
                break
            except Exception as e:
                traceback.print_exc()
                break
    return timer, total_bytes

async def req_per_second(url, kind=9999, limit=50, duration=20, id=0):
    query = {"kinds": [kind], "limit": limit}
    client = ClientSession()
    async with client.ws_connect(url) as ws:
        print(f"connected {id}")
        timer, total_bytes = await asyncio.wait_for(_make_requests(ws, query, limit, duration), timeout=duration+1)

    bps = (total_bytes / timer.duration) / 1024
    print(
        f"\tReq: {timer.count} iterations. {timer.throughput():.1f}/sec {bps:.1f}kBps"
    )
    return timer.count, total_bytes

async def runner(concurrency, func, *args, **kwargs):
    tasks = []
    start = perf_counter()
    for i in range(concurrency):
        kwargs["id"] = i
        tasks.append(asyncio.create_task(func(*args, **kwargs)))

    results = await asyncio.wait(tasks)
    duration = perf_counter() - start
    total_count = 0
    total_bytes = 0
    for r in results[0]:
        count, received = r.result()
        total_count += count
        total_bytes += received
    total_bps = (total_bytes / duration) / (1024 * 1024)
    total_throughput = total_count / duration
    print(f"Total throughput: {total_throughput:.1f}/sec")
    print(f"Total MBps: {total_bps:.1f}MBps")

