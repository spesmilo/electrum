import os
import sys
import json
from collections import defaultdict
from operator import itemgetter
import concurrent
import threading
import queue
import traceback

from sqlalchemy import create_engine, Column, ForeignKey, Integer, String, DateTime, Boolean
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.query import Query
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import not_, or_
from sqlalchemy.orm import scoped_session

from .util import PrintError, standardize_path, TxMinedInfo
from . import transaction

Base = declarative_base()
session_factory = sessionmaker()



class Misc(Base):
    __tablename__ = 'misc'
    key  = Column(String(66), primary_key=True, sqlite_on_conflict_primary_key='REPLACE')
    value = Column(String())

class Txi(Base):
    __tablename__ = 'txi'
    id = Column(Integer, primary_key=True)
    txid = Column(String())
    address = Column(String())
    ser = Column(String())
    v = Column(Integer())

class Txo(Base):
    __tablename__ = 'txo'
    id = Column(Integer, primary_key=True)
    txid = Column(String())
    address = Column(String())
    n = Column(Integer())
    v = Column(Integer())
    is_coinbase = Column(Boolean())

class Transaction(Base):
    __tablename__ = 'transaction'
    txid = Column(String(66), primary_key=True, sqlite_on_conflict_primary_key='REPLACE')
    raw = Column(String())

class Spent(Base):
    __tablename__ = 'spent_outpoints'
    id = Column(Integer, primary_key=True)
    prev_txid = Column(String(66))
    prev_n = Column(Integer())
    ser = Column(String())

class ImportedAddress(Base):
    __tablename__ = 'imported_addresses'
    id = Column(Integer, primary_key=True)
    address = Column(String(66))

class ReceivingAddress(Base):
    __tablename__ = 'receiving_addresses'
    id = Column(Integer, primary_key=True)
    address = Column(String(66))

class ChangeAddress(Base):
    __tablename__ = 'change_addresses'
    id = Column(Integer, primary_key=True)
    address = Column(String(66))

class AddressHistory(Base):
    __tablename__ = 'address_history'
    id = Column(Integer, primary_key=True)
    address = Column(String(66))
    txid = Column(String(66))
    height = Column(Integer)

class Keystore(Base):
    __tablename__ = 'keystore'
    name = Column(String(66), primary_key=True, sqlite_on_conflict_primary_key='REPLACE')
    type = Column(String(10))
    pw_hash_version = Column(Integer())
    seed = Column(String())
    xpub = Column(String())
    xprv = Column(String())

class VerifiedTx(Base):
    __tablename__ = 'verified_tx'
    txid = Column(String(), primary_key=True, sqlite_on_conflict_primary_key='REPLACE')
    height = Column(Integer)
    timestamp = Column(Integer)
    txpos = Column(Integer)
    header_hash = Column(String())

    
class SqliteDB(PrintError):

    def __init__(self, raw, manual_upgrades=False):
        # create db file in memory
        self.tmp_path = '/dev/shm/xx'
        self._modified = True
        with open(self.tmp_path, 'wb') as f:
            f.write(raw)
        self.exists = bool(raw)
        self.requests = queue.Queue()
        threading.Thread(target=self.sql_thread, daemon=True).start()

    def sql_thread(self):
        self.engine = create_engine('sqlite:///' + self.tmp_path, pool_reset_on_return=None, poolclass=StaticPool)#, echo=True)
        self.DBSession = scoped_session(session_factory)
        self.DBSession.configure(bind=self.engine, autoflush=False)
        self.DBSession.remove()
        if not self.exists:
            Base.metadata.create_all(self.engine)
        while True:
            future, func, args, kwargs = self.requests.get()
            try:
                result = func(self, *args, **kwargs)
            except BaseException as e:
                future.set_exception(e)
                continue
            future.set_result(result)

    def sql(func):
        def wrapper(self, *args, **kwargs):
            f = concurrent.futures.Future()
            self.requests.put((f, func, args, kwargs))
            return f.result(timeout=3)
        return wrapper

    def requires_split(self):
        return False

    def requires_upgrade(self):
        return False

    def set_modified(self, b):
        self._modified = b

    def modified(self):
        return self._modified

    def dump(self):
        with open(self.tmp_path, 'rb') as f:
            return f.read()

    def load_addresses(self, x):
        pass

    @sql
    def put(self, key, v):
        if key == 'keystore':
            k = Keystore(name=key, type=v['type'], pw_hash_version=v['pw_hash_version'], seed=v.get('seed'), xpub=v.get('xpub'), xprv=v.get('xprv'))
        else:
            k = Misc(key=key, value=json.dumps(v))
        self.DBSession.add(k)
        self.DBSession.commit()

    @sql
    def get(self, key, default=None):
        if key == 'keystore':
            r = self.DBSession.query(Keystore).filter(Keystore.name == key).one_or_none()
            if r:
                r = {'type':r.type, 'pw_hash_version':r.pw_hash_version, 'seed':r.seed, 'xpub':r.xpub, 'xprv':r.xprv}
        else:
            r = self.DBSession.query(Misc).filter(Misc.key == key).one_or_none()
            if r:
                r = json.loads(r.value)
        return r or default

    @sql
    def add_receiving_address(self, address):
        self.DBSession.add(ReceivingAddress(address=address))
        self.DBSession.commit()

    @sql
    def add_change_address(self, address):
        self.DBSession.add(ChangeAddress(address=address))
        self.DBSession.commit()

    @sql
    def get_receiving_addresses(self):
        return list(map(itemgetter(0), self.DBSession.query(ReceivingAddress.address).all()))

    @sql
    def get_change_addresses(self):
        return list(map(itemgetter(0), self.DBSession.query(ChangeAddress.address).all()))

    @sql
    def num_receiving_addresses(self):
        return self.DBSession.query(ReceivingAddress).count()

    @sql
    def num_change_addresses(self):
        return self.DBSession.query(ChangeAddress).count()

    @sql
    def get_address_index(self, address):
        r = self.DBSession.query(ReceivingAddress).filter(ReceivingAddress.address==address).one_or_none()
        if r:
            return False, r.id - 1
        r = self.DBSession.query(ChangeAddress).filter(ChangeAddress.address==address).one_or_none()
        if r:
            return True, r.id - 1
        r = self.DBSession.query(ImportedAddress).filter(ImportedAddress.address==address).one_or_none()
        if r:
            return r.pubkey

    @sql
    def add_txi_addr(self, txid, address, ser, v):
        if self.DBSession.query(Txi).filter(Txi.txid==txid, Txi.address==address, Txi.ser==ser, Txi.v==v).one_or_none():
            return
        self.DBSession.add(Txi(txid=txid, address=address, ser=ser, v=v))
        self.DBSession.commit()

    @sql
    def add_txo_addr(self, txid, address, n, v, is_coinbase):
        if self.DBSession.query(Txo).filter(Txo.txid==txid, Txo.address==address, Txo.n==n, Txo.v==v, Txo.is_coinbase==is_coinbase).one_or_none():
            return
        self.DBSession.add(Txo(txid=txid, address=address, n=n, v=v, is_coinbase=is_coinbase))
        self.DBSession.commit()

    @sql
    def get_txi(self, txid):
        return set(map(itemgetter(0), self.DBSession.query(Txi.address).filter(Txi.txid==txid).all()))

    @sql
    def get_txo(self, txid):
        return set(map(itemgetter(0), self.DBSession.query(Txo.address).filter(Txo.txid==txid).all()))

    @sql
    def get_txi_addr(self, txid, address):
        return [(r.ser, r.v) for r in self.DBSession.query(Txi).filter(Txi.txid==txid, Txi.address==address).all()]

    @sql
    def get_txo_addr(self, txid, address):
        return [(r.n, r.v, r.is_coinbase) for r in self.DBSession.query(Txo).filter(Txo.txid==txid, Txo.address==address).all()]

    @sql
    def list_txi(self):
        return set(map(itemgetter(0), self.DBSession.query(Txi.txid).all()))

    @sql
    def list_txo(self):
        return set(map(itemgetter(0), self.DBSession.query(Txo.txid).all()))

    @sql
    def get_history(self):
        return set(map(itemgetter(0), self.DBSession.query(AddressHistory.address).all()))

    @sql
    def get_addr_history(self, address):
        return [(x.txid, x.height) for x in self.DBSession.query(AddressHistory).filter(AddressHistory.address==address).all()]

    @sql
    def set_addr_history(self, address, hist):
        for txid, height in hist:
            self.DBSession.add(AddressHistory(address=address, txid=txid, height=height))
        self.DBSession.commit()

    @sql
    def is_in_verified_tx(self, txid):
        return bool(self.DBSession.query(VerifiedTx).filter(VerifiedTx.txid==txid).one_or_none())

    @sql
    def add_verified_tx(self, txid, info):
        self.DBSession.add(VerifiedTx(txid=txid, height=info.height, timestamp=info.timestamp, txpos=info.txpos, header_hash=info.header_hash))
        self.DBSession.commit()

    @sql
    def get_verified_tx(self, txid):
        r = self.DBSession.query(VerifiedTx).filter(VerifiedTx.txid==txid).one_or_none()
        if not r:
            return
        return TxMinedInfo(height=r.height,
                           conf=None,
                           timestamp=r.timestamp,
                           txpos=r.txpos,
                           header_hash=r.header_hash)

    @sql
    def remove_verified_tx(self, txid):
        v = self.DBSession.query(VerifiedTx).filter(VerifiedTx.txid==txid).one_or_none()
        self.DBSession.delete(v)
        self.DBSession.commit()

    @sql
    def get_spent_outpoints(self, prev_txid):
        return [r.prev_n for r in self.DBSession.query(Spent).filter(Spent.prev_txid==prev_txid).all()]

    @sql
    def get_spent_outpoint(self, prev_txid, prev_n):
        r = self.DBSession.query(Spent).filter(Spent.prev_txid==prev_txid, Spent.prev_n==prev_n).one_or_none()
        return r.ser if r else None

    @sql
    def set_spent_outpoint(self, prev_txid, prev_n, ser):
        r = self.DBSession.query(Spent).filter(Spent.prev_txid==prev_txid, Spent.prev_n==prev_n).one_or_none()
        if r:
            return
        self.DBSession.add(Spent(prev_txid=prev_txid, prev_n=prev_n, ser=ser))
        self.DBSession.commit()

    @sql
    def get_transaction(self, txid):
        r = self.DBSession.query(Transaction).filter(Transaction.txid==txid).one_or_none()
        return transaction.Transaction(r.raw) if r else None

    @sql
    def add_transaction(self, txid, tx):
        self.DBSession.add(Transaction(txid=txid, raw=str(tx)))
        self.DBSession.commit()

    @sql
    def update_tx_fees(self, tx_fees):
        pass

    @sql
    def get_tx_fee(self, tx_hash):
        pass
