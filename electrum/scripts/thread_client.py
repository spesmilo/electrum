import logging
import math
import threading
import time
import asyncio
import os
import queue
from asyncio.exceptions import InvalidStateError

from typing import Callable, List, Any

from electrum.network import Network
from electrum.util import print_msg
from electrum.simple_config import SimpleConfig


logging.basicConfig(format='%(asctime)-15s %(levelname)-8s %(message)s', level=logging.INFO)


class ElectrumClient:
    def __init__(self, config: SimpleConfig, loop, stopping_fut, loop_thread):
        self.config = config
        self.loop, self.stopping_fut, self.loop_thread = loop, stopping_fut, loop_thread
        self.network = Network(config)
        self.network.start()
        self.logger = logging.getLogger("ElectrumClient")
        self.results = {}

        while not self.network.is_connected():
            time.sleep(1)
            print_msg("waiting for network to get connected...")

    def run(self, func: Callable, *args, **kwargs):
        asyncio.run_coroutine_threadsafe(func(*args, **kwargs), self.loop)


class ElectrumBatchClient(ElectrumClient):
    def __init__(self, config: SimpleConfig, loop, stopping_fut, loop_thread, batch_limit: int):
        super().__init__(config, loop, stopping_fut, loop_thread)
        self.batch_limit = batch_limit

    @staticmethod
    def chunks(lst, n):
        for i in range(0, len(lst), n):
            yield lst[i:i + n]

    async def get_balances(self, script_hashes: List[str], *args, **kwargs) -> dict:
        self.logger.info(f"start get_balances, count={len(script_hashes)}, batch_lim={self.batch_limit}")
        result = {}
        self.results.update({"get_balances": {}})
        count = 0
        try:
            for shs in self.chunks(script_hashes, self.batch_limit):
                res = await self.network.get_balances_for_scripthashes(shs)
                list(map(lambda i: result.update({shs[i[0]]: i[1]}), enumerate(res)))
                self.results.update({"get_listunspents": result})
                count += len(shs)
                if count % 1000 == 0:
                    self.logger.info(f"thread: {threading.current_thread().ident} count={count}")
        except Exception as e:
            self.logger.error(e)
        finally:
            self.stopping_fut.set_result(self.results)
            self.logger.info(f"stop get_balances. count of processed addresses is {count}")
            return self.results.get("get_balances", {})

    async def get_listunspents(self, script_hashes: List[str], *args, **kwargs) -> dict:
        self.logger.info(f"start get_listunspents, count={len(script_hashes)}, batch_lim={self.batch_limit}")
        self.results.update({"get_listunspents": {}})
        count = 0
        result = {}
        try:
            for shs in self.chunks(script_hashes, self.batch_limit):
                res = await self.network.listunspents_for_scripthashes(shs)
                list(map(lambda i: result.update({shs[i[0]]: i[1]}), enumerate(res)))
                self.results.update({"get_listunspents": result})
                count += len(shs)
                if count % 1000 == 0:
                    self.logger.info(f"thread: {threading.current_thread().ident} count={count}")
                # ipdb.set_trace()
        except Exception as e:
            self.logger.error(e)
        finally:
            try:
                r = self.stopping_fut.result()
            except InvalidStateError:
                r = {}
            r.update(self.results)
            self.stopping_fut.set_result(r)
            self.logger.info(f"stop get_listunspents. count of processed addresses is {count}")
            return self.results.get("get_listunspents", {})


class ElectrumThreadClient(ElectrumBatchClient):
    def __init__(self, config: SimpleConfig, loop, stopping_fut, loop_thread, batch_limit: int):
        super().__init__(config, loop, stopping_fut, loop_thread, batch_limit)
        self.threads_count = int(os.cpu_count()) - 1
        self.threads = []

        self.header_queue = asyncio.Queue()
        self.q = queue.Queue()

    def worker(self, func: Callable, *args, **kwargs):
        while True:
            item = self.q.get()
            if item is None:
                break
            self.do_work(func, *item)
            self.q.task_done()

    def do_work(self, func, *args):
        return self.run(func, args)

    def start(self, func: Callable, params: List[Any]):
        self.logger.info(f"run ElectrumThreadClient.start for func {func.__name__} with {self.threads_count}")
        for i in range(self.threads_count):
            t = threading.Thread(target=self.worker, args=[func])
            t.start()
            self.threads.append(t)
        for chunk in self.chunks(params, math.ceil(len(params) / self.threads_count)):
            self.q.put(chunk)
        self.q.join()

        for i in range(self.threads_count):
            self.q.put(None)
        for t in self.threads:
            t.join()

        while not self.stopping_fut.done():
            time.sleep(1)
        return self.stopping_fut.result().get(func.__name__)
