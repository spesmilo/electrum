import os
import concurrent
import queue
import threading

from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker

from .util import PrintError


def sql(func):
    """wrapper for sql methods"""
    def wrapper(self, *args, **kwargs):
        assert threading.currentThread() != self.sql_thread
        f = concurrent.futures.Future()
        self.db_requests.put((f, func, args, kwargs))
        return f.result(timeout=10)
    return wrapper

class SqlDB(PrintError):
    
    def __init__(self, network, path, base):
        self.base = base
        self.network = network
        self.path = path
        self.db_requests = queue.Queue()
        self.sql_thread = threading.Thread(target=self.run_sql)
        self.sql_thread.start()

    def run_sql(self):
        engine = create_engine('sqlite:///' + self.path, pool_reset_on_return=None, poolclass=StaticPool)#, echo=True)
        DBSession = sessionmaker(bind=engine, autoflush=False)
        self.DBSession = DBSession()
        if not os.path.exists(self.path):
            self.base.metadata.create_all(engine)
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
            future.set_result(result)
        # write
        self.DBSession.commit()
        self.print_error("SQL thread terminated")
