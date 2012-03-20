from Abe.abe import hash_to_address, decode_check_address
from Abe.DataStore import DataStore as Datastore_class
from Abe import DataStore, readconf, BCDataStream,  deserialize, util, base58

import psycopg2, binascii

import thread, traceback, sys, urllib, operator
from json import dumps, loads

dblock = thread.allocate_lock()

class MyStore(Datastore_class):

    def __init__(self,config, address_queue):
        conf = DataStore.CONFIG_DEFAULTS
        args, argv = readconf.parse_argv( [], conf)
        args.dbtype = config.get('database','type')
        if args.dbtype == 'sqlite3':
            args.connect_args = { 'database' : config.get('database','database') }
        elif args.dbtype == 'MySQLdb':
            args.connect_args = { 'db' : config.get('database','database'), 'user' : config.get('database','username'), 'passwd' : config.get('database','password') }
        elif args.dbtype == 'psycopg2':
            args.connect_args = { 'database' : config.get('database','database') }

        Datastore_class.__init__(self,args)

        self.tx_cache = {}
        self.mempool_keys = {}
        self.bitcoind_url = 'http://%s:%s@%s:%s/' % ( config.get('bitcoind','user'), config.get('bitcoind','password'), config.get('bitcoind','host'), config.get('bitcoind','port'))

        self.address_queue = address_queue



    def import_block(self, b, chain_ids=frozenset()):
        block_id = super(MyStore, self).import_block(b, chain_ids)
        #print "block", block_id
        for pos in xrange(len(b['transactions'])):
            tx = b['transactions'][pos]
            if 'hash' not in tx:
                tx['hash'] = util.double_sha256(tx['tx'])
            tx_id = store.tx_find_id_and_value(tx)
            if tx_id:
                self.update_tx_cache(tx_id)
            else:
                print "error: import_block: no tx_id"
        return block_id


    def update_tx_cache(self, txid):
        inrows = self.get_tx_inputs(txid, False)
        for row in inrows:
            _hash = self.binout(row[6])
            address = hash_to_address(chr(0), _hash)
            if self.tx_cache.has_key(address):
                print "cache: invalidating", address
                self.tx_cache.pop(address)
            self.address_queue.put(address)

        outrows = self.get_tx_outputs(txid, False)
        for row in outrows:
            _hash = self.binout(row[6])
            address = hash_to_address(chr(0), _hash)
            if self.tx_cache.has_key(address):
                print "cache: invalidating", address
                self.tx_cache.pop(address)
            self.address_queue.put(address)

    def safe_sql(self,sql, params=(), lock=True):
        try:
            if lock: dblock.acquire()
            ret = self.selectall(sql,params)
            if lock: dblock.release()
            return ret
        except:
            print "sql error", sql
            return []

    def get_tx_outputs(self, tx_id, lock=True):
        return self.safe_sql("""SELECT
                txout.txout_pos,
                txout.txout_scriptPubKey,
                txout.txout_value,
                nexttx.tx_hash,
                nexttx.tx_id,
                txin.txin_pos,
                pubkey.pubkey_hash
              FROM txout
              LEFT JOIN txin ON (txin.txout_id = txout.txout_id)
              LEFT JOIN pubkey ON (pubkey.pubkey_id = txout.pubkey_id)
              LEFT JOIN tx nexttx ON (txin.tx_id = nexttx.tx_id)
             WHERE txout.tx_id = %d 
             ORDER BY txout.txout_pos
        """%(tx_id), (), lock)

    def get_tx_inputs(self, tx_id, lock=True):
        return self.safe_sql(""" SELECT
                txin.txin_pos,
                txin.txin_scriptSig,
                txout.txout_value,
                COALESCE(prevtx.tx_hash, u.txout_tx_hash),
                prevtx.tx_id,
                COALESCE(txout.txout_pos, u.txout_pos),
                pubkey.pubkey_hash
              FROM txin
              LEFT JOIN txout ON (txout.txout_id = txin.txout_id)
              LEFT JOIN pubkey ON (pubkey.pubkey_id = txout.pubkey_id)
              LEFT JOIN tx prevtx ON (txout.tx_id = prevtx.tx_id)
              LEFT JOIN unlinked_txin u ON (u.txin_id = txin.txin_id)
             WHERE txin.tx_id = %d
             ORDER BY txin.txin_pos
             """%(tx_id,), (), lock)

    def get_address_out_rows(self, dbhash):
        return self.safe_sql(""" SELECT
                b.block_nTime,
                cc.chain_id,
                b.block_height,
                1,
                b.block_hash,
                tx.tx_hash,
                tx.tx_id,
                txin.txin_pos,
                -prevout.txout_value
              FROM chain_candidate cc
              JOIN block b ON (b.block_id = cc.block_id)
              JOIN block_tx ON (block_tx.block_id = b.block_id)
              JOIN tx ON (tx.tx_id = block_tx.tx_id)
              JOIN txin ON (txin.tx_id = tx.tx_id)
              JOIN txout prevout ON (txin.txout_id = prevout.txout_id)
              JOIN pubkey ON (pubkey.pubkey_id = prevout.pubkey_id)
             WHERE pubkey.pubkey_hash = ?
               AND cc.in_longest = 1""", (dbhash,))

    def get_address_out_rows_memorypool(self, dbhash):
        return self.safe_sql(""" SELECT
                1,
                tx.tx_hash,
                tx.tx_id,
                txin.txin_pos,
                -prevout.txout_value
              FROM tx 
              JOIN txin ON (txin.tx_id = tx.tx_id)
              JOIN txout prevout ON (txin.txout_id = prevout.txout_id)
              JOIN pubkey ON (pubkey.pubkey_id = prevout.pubkey_id)
             WHERE pubkey.pubkey_hash = ? """, (dbhash,))

    def get_address_in_rows(self, dbhash):
        return self.safe_sql(""" SELECT
                b.block_nTime,
                cc.chain_id,
                b.block_height,
                0,
                b.block_hash,
                tx.tx_hash,
                tx.tx_id,
                txout.txout_pos,
                txout.txout_value
              FROM chain_candidate cc
              JOIN block b ON (b.block_id = cc.block_id)
              JOIN block_tx ON (block_tx.block_id = b.block_id)
              JOIN tx ON (tx.tx_id = block_tx.tx_id)
              JOIN txout ON (txout.tx_id = tx.tx_id)
              JOIN pubkey ON (pubkey.pubkey_id = txout.pubkey_id)
             WHERE pubkey.pubkey_hash = ?
               AND cc.in_longest = 1""", (dbhash,))

    def get_address_in_rows_memorypool(self, dbhash):
        return self.safe_sql( """ SELECT
                0,
                tx.tx_hash,
                tx.tx_id,
                txout.txout_pos,
                txout.txout_value
              FROM tx
              JOIN txout ON (txout.tx_id = tx.tx_id)
              JOIN pubkey ON (pubkey.pubkey_id = txout.pubkey_id)
             WHERE pubkey.pubkey_hash = ? """, (dbhash,))

    def get_history(self, addr):
        
        cached_version = self.tx_cache.get( addr )
        if cached_version is not None:
            return cached_version

        version, binaddr = decode_check_address(addr)
        if binaddr is None:
            return None

        dbhash = self.binin(binaddr)
        rows = []
        rows += self.get_address_out_rows( dbhash )
        rows += self.get_address_in_rows( dbhash )

        txpoints = []
        known_tx = []

        for row in rows:
            try:
                nTime, chain_id, height, is_in, blk_hash, tx_hash, tx_id, pos, value = row
            except:
                print "cannot unpack row", row
                break
            tx_hash = self.hashout_hex(tx_hash)
            txpoint = {
                    "nTime":    int(nTime),
                    "height":   int(height),
                    "is_in":    int(is_in),
                    "blk_hash": self.hashout_hex(blk_hash),
                    "tx_hash":  tx_hash,
                    "tx_id":    int(tx_id),
                    "pos":      int(pos),
                    "value":    int(value),
                    }

            txpoints.append(txpoint)
            known_tx.append(self.hashout_hex(tx_hash))


        # todo: sort them really...
        txpoints = sorted(txpoints, key=operator.itemgetter("nTime"))

        # read memory pool
        rows = []
        rows += self.get_address_in_rows_memorypool( dbhash )
        rows += self.get_address_out_rows_memorypool( dbhash )
        address_has_mempool = False

        for row in rows:
            is_in, tx_hash, tx_id, pos, value = row
            tx_hash = self.hashout_hex(tx_hash)
            if tx_hash in known_tx:
                continue

            # this means that pending transactions were added to the db, even if they are not returned by getmemorypool
            address_has_mempool = True

            # this means pending transactions are returned by getmemorypool
            if tx_hash not in self.mempool_keys:
                continue

            #print "mempool", tx_hash
            txpoint = {
                    "nTime":    0,
                    "height":   0,
                    "is_in":    int(is_in),
                    "blk_hash": 'mempool', 
                    "tx_hash":  tx_hash,
                    "tx_id":    int(tx_id),
                    "pos":      int(pos),
                    "value":    int(value),
                    }
            txpoints.append(txpoint)


        for txpoint in txpoints:
            tx_id = txpoint['tx_id']
            
            txinputs = []
            inrows = self.get_tx_inputs(tx_id)
            for row in inrows:
                _hash = self.binout(row[6])
                address = hash_to_address(chr(0), _hash)
                txinputs.append(address)
            txpoint['inputs'] = txinputs
            txoutputs = []
            outrows = self.get_tx_outputs(tx_id)
            for row in outrows:
                _hash = self.binout(row[6])
                address = hash_to_address(chr(0), _hash)
                txoutputs.append(address)
            txpoint['outputs'] = txoutputs

            # for all unspent inputs, I want their scriptpubkey. (actually I could deduce it from the address)
            if not txpoint['is_in']:
                # detect if already redeemed...
                for row in outrows:
                    if row[6] == dbhash: break
                else:
                    raise
                #row = self.get_tx_output(tx_id,dbhash)
                # pos, script, value, o_hash, o_id, o_pos, binaddr = row
                # if not redeemed, we add the script
                if row:
                    if not row[4]: txpoint['raw_scriptPubKey'] = row[1]

        # cache result
        if not address_has_mempool:
            self.tx_cache[addr] = txpoints
        
        return txpoints



    def memorypool_update(store):

        ds = BCDataStream.BCDataStream()
        previous_transactions = store.mempool_keys
        store.mempool_keys = []

        postdata = dumps({"method": 'getmemorypool', 'params': [], 'id':'jsonrpc'})

        respdata = urllib.urlopen(store.bitcoind_url, postdata).read()
        r = loads(respdata)
        if r['error'] != None:
            return

        v = r['result'].get('transactions')
        for hextx in v:
            ds.clear()
            ds.write(hextx.decode('hex'))
            tx = deserialize.parse_Transaction(ds)
            tx['hash'] = util.double_sha256(tx['tx'])
            tx_hash = store.hashin(tx['hash'])

            store.mempool_keys.append(tx_hash)
            if store.tx_find_id_and_value(tx):
                pass
            else:
                tx_id = store.import_tx(tx, False)
                store.update_tx_cache(tx_id)

        store.commit()


    def main_iteration(store):
        try:
            dblock.acquire()
            store.catch_up()
            store.memorypool_update()

            block_number = store.get_block_number(1)

        except IOError:
            print "IOError: cannot reach bitcoind"
            block_number = 0
        except:
            traceback.print_exc(file=sys.stdout)
            block_number = 0
        finally:
            dblock.release()

        return block_number


