import os
import concurrent
import queue
import threading
import asyncio
import sqlite3

from .logging import Logger


def sql(func):
    """wrapper for sql methods"""
    def wrapper(self, *args, **kwargs):
        assert threading.currentThread() != self.sql_thread
        f = asyncio.Future()
        self.db_requests.put((f, func, args, kwargs))
        return f
    return wrapper

class SqlDB(Logger):
    
    def __init__(self, network, path, commit_interval=None):
        Logger.__init__(self)
        self.network = network
        self.path = path
        self.commit_interval = commit_interval
        self.db_requests = queue.Queue()
        self.sql_thread = threading.Thread(target=self.run_sql)
        self.sql_thread.start()

    def run_sql(self):
        self.logger.info("SQL thread started")
        self.conn = sqlite3.connect(self.path)
        self.logger.info("Creating database")
        self.create_database()
        i = 0
        while self.network.asyncio_loop.is_running():
            try:
                future, func, args, kwargs = self.db_requests.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                result = func(self, *args, **kwargs)
            except BaseException as e:
                future.set_exception(e)
                continue
            if not future.cancelled():
                future.set_result(result)
            # note: in sweepstore session.commit() is called inside
            # the sql-decorated methods, so commiting to disk is awaited
            if self.commit_interval:
                i = (i + 1) % self.commit_interval
                if i == 0:
                    self.conn.commit()
        # write
        self.conn.commit()
        self.conn.close()
        self.logger.info("SQL thread terminated")
