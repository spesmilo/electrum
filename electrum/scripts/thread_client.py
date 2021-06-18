import logging
import math
import threading
import time
import asyncio
import os
import queue
from asyncio.exceptions import InvalidStateError

from typing import Callable, List, Any

import ipdb

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

        while not self.network.is_connected():
            time.sleep(1)
            print_msg("waiting for network to get connected...")

    def run(self, func: Callable, *args, **kwargs):
        a = asyncio.run_coroutine_threadsafe(func(*args, **kwargs), self.loop)
        while not a.done():
            time.sleep(1)
        return a.result()


class ElectrumBatchClient(ElectrumClient):
    def __init__(self, config: SimpleConfig, loop, stopping_fut, loop_thread, batch_limit: int):
        super().__init__(config, loop, stopping_fut, loop_thread)
        self.batch_limit = batch_limit
        self.results = {}
        self.cc = 0

    @staticmethod
    def chunks(lst, n):
        for i in range(0, len(lst), n):
            yield lst[i:i + n]

    async def get_balances(self, script_hashes: List[str], *args, **kwargs) -> dict:
        self.logger.info(f"start get_balances in thread #{kwargs.get('thread_numb', 0)}, count={len(script_hashes)}, batch_lim={self.batch_limit}")

        result = {}
        count = 0

        try:
            for shs in self.chunks(script_hashes, self.batch_limit):
                res = await self.network.get_balances_for_scripthashes(shs)
                list(map(lambda i: result.update({shs[i[0]]: i[1]}), enumerate(res)))
                count += len(shs)
                if count % 1000 == 0:
                    self.logger.info(f"thread #{kwargs.get('thread_numb', 0)} -- count={count}")
        except Exception as e:
            self.logger.error(e)
        finally:
            self.logger.warning("FINISH")
            self.logger.info(f"stop get_balances in thread #{kwargs.get('thread_numb', 0)}. count of processed addresses is {count}")
            return result

    async def get_listunspents(self, script_hashes: List[str], *args, **kwargs) -> dict:
        self.logger.info(f"start get_listunspents in thread #{kwargs.get('thread_numb', 0)}, count={len(script_hashes)}, batch_lim={self.batch_limit} ---- {script_hashes[0]}")
        count = 0
        result = {}
        try:
            for shs in self.chunks(script_hashes, self.batch_limit):
                res = await self.network.listunspents_for_scripthashes(shs)
                list(map(lambda i: result.update({shs[i[0]]: i[1]}), enumerate(res)))
                count += len(shs)
                if count % 1000 == 0:
                    self.logger.info(f"thread #{kwargs.get('thread_numb', 0)} -- count={count}")
        except Exception as e:
            self.logger.error(e)
        finally:
            self.logger.warning("FINISH kwargs.get('thread_number')")
            self.logger.info(f"stop get_listunspents in thread #{kwargs.get('thread_numb', 0)}. count of processed addresses is {count},")
            return result

    async def get_listmempools(self, script_hashes: List[str], *args, **kwargs) -> dict:
        self.logger.info(f"start listmempools_for_scripthashes in thread #{kwargs.get('thread_numb', 0)}, count={len(script_hashes)}, batch_lim={self.batch_limit} ---- {script_hashes[0]}")
        count = 0
        result = {}
        try:
            for shs in self.chunks(script_hashes, self.batch_limit):
                res = await self.network.listmempools_for_scripthashes(shs)
                list(map(lambda i: result.update({shs[i[0]]: i[1]}), enumerate(res)))
                count += len(shs)
                if count % 1000 == 0:
                    self.logger.info(f"thread #{kwargs.get('thread_numb', 0)} -- count={count}")
        except Exception as e:
            self.logger.error(e)
        finally:
            self.logger.warning("FINISH kwargs.get('thread_number')")
            self.logger.info(f"stop listmempools_for_scripthashes in thread #{kwargs.get('thread_numb', 0)}. count of processed addresses is {count},")
            return result


class ElectrumThreadClient(ElectrumBatchClient):
    def __init__(self, config: SimpleConfig, loop, stopping_fut, loop_thread, batch_limit: int):
        self.threads_count = int(os.cpu_count()) - 1
        self.threads = []

        self.header_queue = asyncio.Queue()
        self.q = queue.Queue()
        super().__init__(config, loop, stopping_fut, loop_thread, batch_limit)

    def worker(self, func: Callable, *args, **kwargs):
        while True:
            item = self.q.get()
            if item is None:
                break
            self.do_work(func, *item)
            self.q.task_done()

    def do_work(self, func, params, thread_numb=0):
        res = self.run(func, params, thread_numb=thread_numb)
        self.logger.info(f"data: {len(res)}")
        return self.result.update(res)

    def start(self, func: Callable, params: List[Any]):
        self.logger.info(f"run ElectrumThreadClient.start for func {func.__name__} with {self.threads_count} threads")
        for i, chunk in enumerate(self.chunks(params, math.ceil(len(params) / self.threads_count))):
            t = threading.Thread(target=self.do_work, args=[func, chunk, i], name=f"thread #{i}")
            t.start()
            self.threads.append(t)

        for t in self.threads:
            t.join()

        self.logger.warning("FUCK")
        return self.result

    def __enter__(self):
        self.result = {}
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        asyncio.run(self.network.stop())
