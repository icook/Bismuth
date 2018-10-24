# c = hyperblock in ram OR hyperblock file when running only hyperblocks
# h = ledger file
# h2 = hyperblock file
# h3 = ledger file OR hyperblock file when running only hyperblocks

# never remove the str() conversion in data evaluation or database inserts or you will debug for 14 days as signed types mismatch
# if you raise in the server thread, the server will die and node will stop
# never use codecs, they are bugged and do not provide proper serialization
# must unify node and client now that connections parameters are function parameters
# if you have a block of data and want to insert it into sqlite, you must use a single "commit" for the whole batch, it's 100x faster
# do not isolation_level=None/WAL hdd levels, it makes saving slow


import shutil, socketserver, base64, hashlib, os, re, sqlite3, sys, threading, time, socks, random, math, requests, tarfile, glob

from decimal import *
from hashlib import blake2b
from Cryptodome.Hash import SHA
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5

from bismuth.core.utils import quantize_two, quantize_eight, quantize_ten
from bismuth.core.ann import ann_get, ann_ver_get
from bismuth.core.essentials import fee_calculate
from bismuth.core.utils import send, receive
from bismuth.core import mempool as mp, plugins, staking, mining, mining_heavy3, regnet, aliases, tokensv2 as tokens, log, options, peers_manager, peer_handler, apihandler as apihandler_module, keys, essentials

getcontext().rounding = ROUND_HALF_EVEN

PEM_BEGIN = re.compile(r"\s*-----BEGIN (.*)-----\s+")
PEM_END = re.compile(r"-----END (.*)-----\s*$")


def validate_pem(public_key):
    """ Validate PEM data against :param public key:

    :param public_key: public key to validate PEM against

    The PEM data is constructed by base64 decoding the public key
    Then, the data is tested against the PEM_BEGIN and PEM_END
    to ensure the `pem_data` is valid, thus validating the public key.

    returns None
    """
    # verify pem as cryptodome does
    pem_data = base64.b64decode(public_key).decode("utf-8")
    match = PEM_BEGIN.match(pem_data)
    if not match:
        raise ValueError("Not a valid PEM pre boundary")

    marker = match.group(1)

    match = PEM_END.search(pem_data)
    if not match or match.group(1) != marker:
        raise ValueError("Not a valid PEM post boundary")
        # verify pem as cryptodome does


def download_file(url, filename):
    """Download a file from URL to filename

    :param url: URL to download file from
    :param filename: Filename to save downloaded data as

    returns `filename`
    """
    try:
        r = requests.get(url, stream=True)
        total_size = int(r.headers.get('content-length')) / 1024

        with open(filename, 'wb') as filename:
            chunkno = 0
            for chunk in r.iter_content(chunk_size=1024):
                if chunk:
                    chunkno = chunkno + 1
                    if chunkno % 10000 == 0:  # every x chunks
                        print("Downloaded {} %".format(int(100 * ((chunkno) / total_size))))

                    filename.write(chunk)
                    filename.flush()
            print("Downloaded 100 %")

        return filename
    except:
        raise

def most_common(lst):
    return max(set(lst), key=lst.count)


def percentage(percent, whole):
    return Decimal(percent) * Decimal(whole) / 100

def bin_convert(string):
    return ''.join(format(ord(x), '8b').replace(' ', '0') for x in string)

def just_int_from(s):
    return int(''.join(i for i in s if i.isdigit()))

class Node:
    POW_FORK = 854660
    FORK_AHEAD = 5
    FORK_DIFF = 108.9
    VERSION = "4.2.8"  # 3. regnet support

    def __init__(self):
        # Most of the globals from the top of node.py
        self.config = options.Get()
        self.config.read()
        self.IS_STOPPING = False
        self.hdd_block = 0
        self.last_block = 0
        self.is_testnet = False
        # regnet takes over testnet
        self.is_regnet = False
        # if it's not testnet, nor regnet, it's mainnet
        self.is_mainnet = True

        self.conn = None
        self.c = None
        self.h3 = None
        self.startup_time = time.time()
        self.syncing = []

        self.dl_lock = threading.Lock()
        self.db_lock = threading.Lock()

        self.appname = "Bismuth"
        self.appauthor = "Bismuth Foundation"

        # Basically the guts of __name__ == __main__ from old node.py
        # ######################################################
        self.app_log = log.log("node.log", self.config.debug_level_conf, self.config.terminal_output)
        self.app_log.warning("Configuration settings loaded")


    def start(self):
        # create a plugin manager, load all plugin modules and init
        self.plugin_manager = plugins.PluginManager(app_log=self.app_log, init=True)

        self.setup_net_type()
        self.load_keys()
        self.initial_db_check()

        self.peers = peers_manager.Peers(self.app_log, self.config)
        self.apihandler = apihandler_module.ApiHandler(self.app_log, self.config)

        mp.MEMPOOL = mp.Mempool(self.app_log, self.config, self.db_lock, self.is_testnet)

        if self.config.rebuild_db_conf:
            self.db_maintenance(self.conn)

        if self.config.verify_conf:
            self.verify(self.h3)

        if not self.config.tor_conf:
            # Port 0 means to select an arbitrary unused port
            HOST, PORT = "0.0.0.0", int(self.config.port)

            class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
                pass

            ThreadedTCPServer.allow_reuse_address = True
            ThreadedTCPServer.daemon_threads = True
            ThreadedTCPServer.timeout = 60
            ThreadedTCPServer.request_queue_size = 100
            ThreadedTCPServer.node = self

            server = ThreadedTCPServer((HOST, PORT), peer_handler.ThreadedTCPRequestHandler)
            ip, port = server.server_address

            # Start a thread with the server -- that thread will then start one
            # more thread for each request

            server_thread = threading.Thread(target=server.serve_forever)

            # Exit the server thread when the main thread terminates

            server_thread.daemon = True
            server_thread.start()
            self.app_log.warning("Status: Server loop running on {}:{}".format(HOST, PORT))
        else:
            self.app_log.warning("Status: Not starting a local server to conceal identity on Tor network")

        # start connection manager
        t_manager = threading.Thread(target=self.manager(self.c))
        self.app_log.warning("Status: Starting connection manager")
        t_manager.daemon = True
        # start connection manager
        t_manager.start()
        if not self.is_regnet:
            # regnet mode does not need any specific attention.
            self.app_log.warning("Closing in 10 sec...")
            time.sleep(10)
        # server.serve_forever() #added
        server.shutdown()
        server.server_close()
        mp.MEMPOOL.close()

    def setup_net_type(self):
        """
        Adjust globals depending on mainnet, testnet or regnet
        """

        # Defaults value, dup'd here for clarity sake.
        self.is_mainnet = True
        self.is_testnet = False
        self.is_regnet = False

        if "testnet" in self.config.version or self.config.testnet:
            self.is_testnet = True
            self.is_mainnet = False

        if "regnet" in self.config.version or self.config.regnet:
            self.is_regnet = True
            self.is_testnet = False
            self.is_mainnet = False

        self.app_log.warning("Testnet: {}".format(self.is_testnet))
        self.app_log.warning("Regnet : {}".format(self.is_regnet))

        # default mainnet config
        self.peerlist = "peers.txt"
        self.ledger_ram_file = "file:ledger?mode=memory&cache=shared"
        self.index_db = "static/index.db"

        if self.is_mainnet:
            # Allow 18 for transition period. Will be auto removed at fork block.
            if self.config.version != 'mainnet0020':
                self.config.version = 'mainnet0019'  # Force in code.
            if "mainnet0020" not in self.config.version_allow:
                version_allow = ['mainnet0019', 'mainnet0020', 'mainnet0021']
            # Do not allow bad configs.
            if not 'mainnet' in self.config.version:
                self.app_log.error("Bad mainnet version, check config.txt")
                sys.exit()
            num_ver = just_int_from(self.config.version)
            if num_ver < 19:
                self.app_log.error("Too low mainnet version, check config.txt")
                sys.exit()
            for allowed in version_allow:
                num_ver = just_int_from(allowed)
                if num_ver < 19:
                    self.app_log.error("Too low allowed version, check config.txt")
                    sys.exit()

        if self.is_testnet:
            self.config.port = 2829
            # TODO: Why is this?
            self.config.full_ledger = False
            self.config.hyper_path_conf = "static/test.db"
            self.config.ledger_path_conf = "static/test.db"  # for tokens
            self.config.hyper_recompress_conf = False
            self.ledger_ram_file = "file:ledger_testnet?mode=memory&cache=shared"
            self.peerlist = "peers_test.txt"
            self.index_db = "static/index_test.db"
            if not 'testnet' in self.config.version:
                self.app_log.error("Bad testnet version, check config.txt")
                sys.exit()

            redownload_test = input("Status: Welcome to the testnet. Redownload test ledger? y/n")
            if redownload_test == "y" or not os.path.exists("static/test.db"):
                types = ['static/test.db-wal', 'static/test.db-shm', 'static/index_test.db']
                for type in types:
                    for file in glob.glob(type):
                        os.remove(file)
                        print(file, "deleted")
                download_file("https://bismuth.cz/test.db", "static/test.db")
                download_file("https://bismuth.cz/index_test.db", "static/index_test.db")
            else:
                print("Not redownloading test db")

        if self.is_regnet:
            self.config.port = regnet.REGNET_PORT
            self.config.hyper_path_conf = regnet.REGNET_DB
            self.config.ledger_path_conf = regnet.REGNET_DB
            self.config.hyper_recompress_conf = False
            self.ledger_ram_file = "file:ledger_regnet?mode=memory&cache=shared"
            self.peerlist = regnet.REGNET_PEERS
            self.index_db = regnet.REGNET_INDEX
            if not 'regnet' in self.config.version:
                self.app_log.error("Bad regnet version, check config.txt")
                sys.exit()
            self.app_log.warning("Regnet init...")
            regnet.init(self.app_log)
            regnet.DIGEST_BLOCK = self.digest_block
            mining_heavy3.is_regnet = True
            """
            app_log.warning("Regnet still is WIP atm.")
            sys.exit()
            """
    def load_keys(self):
        """Initial loading of crypto keys"""
        essentials.keys_check(self.app_log, "wallet.der")
        essentials.db_check(self.app_log)
        self.key, self.public_key_readable, self.private_key_readable, _, _, self.public_key_hashed, self.address, self.keyfile = \
            essentials.keys_load("privkey.der", "pubkey.der")
        if self.is_regnet:
            regnet.PRIVATE_KEY_READABLE = self.private_key_readable
            regnet.PUBLIC_KEY_HASHED = self.public_key_hashed
            regnet.ADDRESS = self.address
            regnet.KEY = self.key

        self.app_log.warning("Status: Local address: {}".format(self.address))

    def initial_db_check(self):
        """
        Initial bootstrap check and chain validity control
        """
        # global last_block, hdd_block
        # global tr, conn, c, hdd, h, h3, hdd2, h2, plugin_manager
        # force bootstrap via adding an empty "fresh_sync" file in the dir.
        if os.path.exists("fresh_sync") and self.is_mainnet:
            self.app_log.warning("Status: Fresh sync required, bootstrapping from the website")
            os.remove("fresh_sync")
            self.bootstrap()
        # UPDATE mainnet DB if required
        if self.is_mainnet:
            # TODO: Shouldn't this use db_h2_define?
            upgrade = sqlite3.connect(self.config.ledger_path_conf)
            u = upgrade.cursor()
            try:
                u.execute("PRAGMA table_info(transactions);")
                result = u.fetchall()[10][2]
                if result != "TEXT":
                    raise ValueError("Database column type outdated for Command field")
                upgrade.close()
            except Exception as e:
                upgrade.close()
                self.app_log.warning("Database needs upgrading, bootstrapping...", exc_info=True)
                self.bootstrap()
            # UPDATE DB
            self.check_integrity(self.config.hyper_path_conf)
            self.coherence_check()

        self.app_log.warning("Status: Indexing tokens from ledger {}".format(self.config.ledger_path_conf))
        tokens.tokens_update(self.index_db, self.config.ledger_path_conf, "normal", self.app_log, self.plugin_manager)
        self.app_log.warning("Status: Indexing aliases")
        aliases.aliases_update(self.index_db, self.config.ledger_path_conf, "normal", self.app_log)
        self.ledger_compress()
        self.app_log.debug("Status: Ledger compression complete")

        try:
            source_db = sqlite3.connect(self.config.hyper_path_conf, timeout=1)
            source_db.text_factory = str
            sc = source_db.cursor()

            sc.execute("SELECT max(block_height) FROM transactions")
            self.hdd_block = sc.fetchone()[0]

            self.last_block = self.hdd_block

            if self.is_mainnet and (self.hdd_block >= self.POW_FORK - self.FORK_AHEAD):
                self.limit_version()

            if self.config.ram_conf:
                self.app_log.warning("Status: Moving database to RAM")
                to_ram = sqlite3.connect(self.ledger_ram_file, uri=True, timeout=1, isolation_level=None)
                to_ram.text_factory = str
                tr = to_ram.cursor()

                query = "".join(line for line in source_db.iterdump())
                to_ram.executescript(query)
                # do not close
                self.app_log.warning("Status: Moved database to RAM")

        except Exception as e:
            # TODO: FIXME
            self.app_log.error(e)
            sys.exit()

        # mempool, m = db_m_define()
        conn, c = self.db_c_define()
        self.c = c
        hdd2, h2 = self.db_h2_define()
        self.hdd2 = hdd2
        if self.config.full_ledger:
            hdd, h = self.db_h_define()
            self.h3 = h
        else:
            hdd, h = None, None
            self.h3 = h2

    def db_c_define(self):
        try:
            if self.config.ram_conf:
                self.conn = sqlite3.connect(self.ledger_ram_file, uri=True, timeout=1, isolation_level=None)
            else:
                self.conn = sqlite3.connect(self.config.hyper_path_conf, uri=True, timeout=1, isolation_level=None)

            self.conn.execute('PRAGMA journal_mode = WAL;')
            self.conn.execute("PRAGMA page_size = 4096;")
            self.conn.text_factory = str
            self.c = self.conn.cursor()

        except Exception as e:
            self.app_log.info("Failed to load ledger db", exc_info=True)

        return self.conn, self.c

    def db_h_define(self):
        hdd = sqlite3.connect(self.config.ledger_path_conf, timeout=1)
        hdd.text_factory = str
        h = hdd.cursor()
        hdd.execute("PRAGMA page_size = 4096;")
        return hdd, h

    def db_h2_define(self):
        hdd2 = sqlite3.connect(self.config.hyper_path_conf, timeout=1)
        hdd2.text_factory = str
        h2 = hdd2.cursor()
        hdd2.execute("PRAGMA page_size = 4096;")
        return hdd2, h2

    def index_define(self):
        index = sqlite3.connect(self.index_db, timeout=1)
        index.text_factory = str
        index_cursor = index.cursor()
        index.execute("PRAGMA page_size = 4096;")
        return index, index_cursor

    def difficulty(self, c):
        self.execute(c, "SELECT * FROM transactions WHERE reward != 0 ORDER BY block_height DESC LIMIT 2")
        result = c.fetchone()
        timestamp_last = Decimal(result[1])
        block_height = int(result[0])
        previous = c.fetchone()
        # Failsafe for regtest starting at block 1}
        timestamp_before_last = timestamp_last if previous is None else Decimal(previous[1])

        self.execute_param(c, ("SELECT timestamp FROM transactions WHERE CAST(block_height AS INTEGER) > ? AND reward != 0 ORDER BY timestamp ASC LIMIT 2"), (block_height - 1441,))
        timestamp_1441 = Decimal(c.fetchone()[0])
        block_time_prev = (timestamp_before_last - timestamp_1441) / 1440
        temp = c.fetchone()
        timestamp_1440 = timestamp_1441 if temp is None else Decimal(temp[0])
        block_time = Decimal(timestamp_last - timestamp_1440) / 1440
        self.execute(c, ("SELECT difficulty FROM misc ORDER BY block_height DESC LIMIT 1"))
        diff_block_previous = Decimal(c.fetchone()[0])

        time_to_generate = timestamp_last - timestamp_before_last

        if self.is_regnet:
            return (float('%.10f' % regnet.REGNET_DIFF), float('%.10f' % (regnet.REGNET_DIFF - 8)), float(time_to_generate),
                float(regnet.REGNET_DIFF), float(block_time), float(0), float(0), block_height)

        hashrate = pow(2, diff_block_previous / Decimal(2.0)) / (
            block_time * math.ceil(28 - diff_block_previous / Decimal(16.0)))
        # Calculate new difficulty for desired blocktime of 60 seconds
        target = Decimal(60.00)
        ##D0 = diff_block_previous
        difficulty_new = Decimal((2 / math.log(2)) * math.log(hashrate * target * math.ceil(28 - diff_block_previous / Decimal(16.0))))
        # Feedback controller
        Kd = 10
        difficulty_new = difficulty_new - Kd * (block_time - block_time_prev)
        diff_adjustment = (difficulty_new - diff_block_previous) / 720  # reduce by factor of 720

        if diff_adjustment > Decimal(1.0):
            diff_adjustment = Decimal(1.0)

        difficulty_new_adjusted = quantize_ten(diff_block_previous + diff_adjustment)
        difficulty = difficulty_new_adjusted

        if self.is_mainnet:
            if block_height == self.POW_FORK - self.FORK_AHEAD:
                self.limit_version()
            if block_height == self.POW_FORK - 1:
                difficulty = self.FORK_DIFF
            if block_height == self.POW_FORK:
                difficulty = self.FORK_DIFF
                # Remove mainnet0018 from allowed
                self.limit_version()
                # disconnect our outgoing connections

        diff_drop_time = Decimal(180)

        if Decimal(time.time()) > Decimal(timestamp_last) + Decimal(2*diff_drop_time):
            # Emergency diff drop
            time_difference = quantize_two(time.time()) - quantize_two(timestamp_last)
            diff_dropped = quantize_ten(difficulty) - quantize_ten(1) \
                           - quantize_ten(10 * (time_difference-2 * diff_drop_time) / diff_drop_time)
        elif Decimal(time.time()) > Decimal(timestamp_last) + Decimal(diff_drop_time):
            time_difference = quantize_two(time.time()) - quantize_two(timestamp_last)
            diff_dropped = quantize_ten(difficulty) + quantize_ten(1) - quantize_ten(time_difference / diff_drop_time)
        else:
            diff_dropped = difficulty

        if difficulty < 50:
            difficulty = 50
        if diff_dropped < 50:
            diff_dropped = 50

        return (
            float('%.10f' % difficulty), float('%.10f' % diff_dropped), float(time_to_generate), float(diff_block_previous),
            float(block_time), float(hashrate), float(diff_adjustment),
            block_height)  # need to keep float here for database inserts support

    def limit_version(self):
        if 'mainnet0018' in self.config.version_allow:
            self.app_log.warning("Beginning to reject mainnet0018 - block {}".format(self.last_block))
            self.config.version_allow.remove('mainnet0018')

    def tokens_rollback(self, height, app_log):
        """Rollback Token index

        :param height: height index of token in chain
        :param app_log: logger to use

        Simply deletes from the `tokens` table where the block_height is
        greater than or equal to the :param height: and logs the new height

        returns None
        """
        with sqlite3.connect(self.index_db) as tok:
            t = tok.cursor()
            self.execute_param(t, "DELETE FROM tokens WHERE block_height >= ?;", (height - 1,))
            self.commit(tok)
        self.app_log.warning("Rolled back the token index to {}".format(height - 1))


    def staking_rollback(self, height, app_log):
        """Rollback staking index

        :param height: height index of token in chain
        :param app_log: logger to use

        Simply deletes from the `staking` table where the block_height is
        greater than or equal to the :param height: and logs the new height

        returns None
        """
        with sqlite3.connect(self.index_db) as sta:
            s = sta.cursor()
            self.execute_param(s, "DELETE FROM staking WHERE block_height >= ?;", (height - 1,))
            self.commit(sta)
        self.app_log.warning("Rolled back the staking index to {}".format(height - 1))


    def aliases_rollback(self, height, app_log):
        """Rollback Alias index

        :param height: height index of token in chain
        :param app_log: logger to use

        Simply deletes from the `aliases` table where the block_height is
        greater than or equal to the :param height: and logs the new height

        returns None
        """
        with sqlite3.connect(self.index_db) as ali:
            a = ali.cursor()
            self.execute_param(a, "DELETE FROM aliases WHERE block_height >= ?;", (height - 1,))
            self.commit(ali)
        self.app_log.warning("Rolled back the alias index to {}".format(height - 1))

    def sendsync(self, sdef, peer_ip, status, provider):
        """ Save peer_ip to peerlist and send `sendsync`

        :param sdef: socket object
        :param peer_ip: IP of peer synchronization has been completed with
        :param status: Status synchronization was completed in/as
        :param provider: <Documentation N/A>

        Log the synchronization status
        Save peer IP to peers list if applicable
        Wait for database to unlock
        Send `sendsync` command via socket `sdef`

        returns None
        """

        self.app_log.info("Outbound: Synchronization with {} finished after: {}, sending new sync request".format(peer_ip, status))

        if provider:
            self.app_log.info("Outbound: Saving peer {}".format(peer_ip))
            self.peers.peers_save(peer_ip)

        time.sleep(Decimal(self.config.pause_conf))
        while self.db_lock.locked():
            if self.IS_STOPPING:
                return
            time.sleep(Decimal(self.config.pause_conf))

        send(sdef, "sendsync")

    def commit(self, cursor):
        """Secure commit for slow nodes"""
        while not self.IS_STOPPING:
            try:
                cursor.commit()
                break
            except Exception as e:
                self.app_log.warning("Database cursor: {}".format(cursor))
                self.app_log.warning("Database retry reason: {}".format(e))
                time.sleep(0.1)

    def execute(self, cursor, query):
        """Secure execute for slow nodes"""
        while not self.IS_STOPPING:
            try:
                cursor.execute(query)
                break
            except sqlite3.InterfaceError as e:
                self.app_log.warning("Database query to abort: {} {}".format(cursor, query))
                self.app_log.warning("Database abortion reason: {}".format(e))
                break
            except sqlite3.IntegrityError as e:
                self.app_log.warning("Database query to abort: {} {}".format(cursor, query))
                self.app_log.warning("Database abortion reason: {}".format(e))
                break
            except Exception as e:
                self.app_log.warning("Database query: {} {}".format(cursor, query))
                self.app_log.warning("Database retry reason: {}".format(e))
                time.sleep(1)
        return cursor

    def execute_param(self, cursor, query, param):
        """Secure execute w/ param for slow nodes"""
        while not self.IS_STOPPING:
            try:
                cursor.execute(query, param)
                break
            except sqlite3.InterfaceError as e:
                self.app_log.warning("Database query to abort: {} {} {}".format(cursor, query, param))
                self.app_log.warning("Database abortion reason: {}".format(e))
                break
            except sqlite3.IntegrityError as e:
                self.app_log.warning("Database query to abort: {} {}".format(cursor, query))
                self.app_log.warning("Database abortion reason: {}".format(e))
                break
            except Exception as e:
                self.app_log.warning("Database query: {} {} {}".format(cursor, query, param))
                self.app_log.warning("Database retry reason: {}".format(e))
                time.sleep(1)
        return cursor

    def db_to_drive(self, hdd, h, hdd2, h2):
        self.app_log.warning("Block: Moving new data to HDD")
        try:
            if self.config.ram_conf:  # select RAM as source database
                source_db = sqlite3.connect(self.ledger_ram_file, uri=True, timeout=1)
            else:  # select hyper.db as source database
                source_db = sqlite3.connect(self.config.hyper_path_conf, timeout=1)

            source_db.text_factory = str
            sc = source_db.cursor()

            self.execute_param(sc, (
                "SELECT * FROM transactions WHERE block_height > ? OR block_height < ? ORDER BY block_height ASC"),
                          (self.hdd_block, -self.hdd_block))
            result1 = sc.fetchall()

            if self.config.full_ledger:  # we want to save to ledger.db
                for x in result1:
                    h.execute("INSERT INTO transactions VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                              (x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], x[8], x[9], x[10], x[11]))
                self.commit(hdd)

            if self.config.ram_conf:  # we want to save to hyper.db from RAM/hyper.db depending on ram conf
                for x in result1:
                    h2.execute("INSERT INTO transactions VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                               (x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], x[8], x[9], x[10], x[11]))
                self.commit(hdd2)

            self.execute_param(sc, ("SELECT * FROM misc WHERE block_height > ? ORDER BY block_height ASC"), (self.hdd_block,))
            result2 = sc.fetchall()

            if self.config.full_ledger:  # we want to save to ledger.db from RAM/hyper.db depending on ram conf
                for x in result2:
                    h.execute("INSERT INTO misc VALUES (?,?)", (x[0], x[1]))
                self.commit(hdd)

            if self.config.ram_conf:  # we want to save to hyper.db from RAM
                for x in result2:
                    h2.execute("INSERT INTO misc VALUES (?,?)", (x[0], x[1]))
                self.commit(hdd2)

            h2.execute("SELECT max(block_height) FROM transactions")
            self.hdd_block = h2.fetchone()[0]
        except Exception as e:
            self.app_log.warning("Block: Exception Moving new data to HDD: {}".format(e))
            self.app_log.deubg("Ledger digestion ended")  # dup with more informative digest_block notice.

    def ledger_compress(self):
        """conversion of normal blocks into hyperblocks from ledger.db or hyper.db to hyper.db"""
        try:

            # if os.path.exists(hyper_path_conf+".temp"):
            #    os.remove(hyper_path_conf+".temp")
            #    app_log.warning("Status: Removed old temporary hyperblock file")
            #    time.sleep(100)

            if os.path.exists(self.config.hyper_path_conf):

                if self.config.full_ledger:
                    # cross-integrity check
                    hdd = sqlite3.connect(self.config.ledger_path_conf, timeout=1)
                    hdd.text_factory = str
                    h = hdd.cursor()
                    h.execute("SELECT max(block_height) FROM transactions")
                    hdd_block_last = h.fetchone()[0]
                    hdd.close()

                    hdd2 = sqlite3.connect(self.config.hyper_path_conf, timeout=1)
                    hdd2.text_factory = str
                    h2 = hdd2.cursor()
                    h2.execute("SELECT max(block_height) FROM transactions")
                    hdd2_block_last = h2.fetchone()[0]
                    hdd2.close()
                    # cross-integrity check

                    if hdd_block_last == hdd2_block_last and self.config.hyper_recompress_conf:  # cross-integrity check
                        self.config.ledger_path_conf = self.config.hyper_path_conf  # only valid within the function, this temporarily sets hyper.db as source
                        self.app_log.warning("Status: Recompressing hyperblocks (keeping full ledger)")
                        recompress = True
                    elif hdd_block_last == hdd2_block_last and self.config.hyper_recompress_conf:
                        self.app_log.warning("Status: Hyperblock recompression skipped")
                        recompress = False
                    else:
                        self.app_log.warning(
                            "Status: Cross-integrity check failed, hyperblocks will be rebuilt from full ledger")
                        recompress = True
                else:
                    if self.config.hyper_recompress_conf:
                        self.app_log.warning("Status: Recompressing hyperblocks (without full ledger)")
                        recompress = True
                    else:
                        self.app_log.warning("Status: Hyperblock recompression skipped")
                        recompress = False
            else:
                self.app_log.warning("Status: Compressing ledger to Hyperblocks")
                recompress = True

            if recompress:
                depth = 15000  # REWORK TO REFLECT TIME INSTEAD OF BLOCKS

                # if os.path.exists(ledger_path_conf + '.temp'):
                #    os.remove(ledger_path_conf + '.temp')

                if self.config.full_ledger:
                    shutil.copy(self.config.ledger_path_conf, self.config.ledger_path_conf + '.temp')
                    hyper = sqlite3.connect(self.config.ledger_path_conf + '.temp')
                else:
                    shutil.copy(self.config.hyper_path_conf, self.config.ledger_path_conf + '.temp')
                    hyper = sqlite3.connect(self.config.ledger_path_conf + '.temp')

                hyper.text_factory = str
                hyp = hyper.cursor()

                addresses = []

                hyp.execute("UPDATE transactions SET address = 'Hypoblock' WHERE address = 'Hyperblock'")

                hyp.execute("SELECT max(block_height) FROM transactions")
                db_block_height = int(hyp.fetchone()[0])
                depth_specific = db_block_height - depth
                self.app_log.warning("Max height {:,}, compressing to depth {:,}"
                                   .format(db_block_height, depth_specific))

                hyp.execute("SELECT distinct(recipient) FROM transactions WHERE (block_height < ?) ORDER BY block_height;", (depth_specific,))  # new addresses will be ignored until depth passed
                unique_addressess = hyp.fetchall()
                self.app_log.warning("Checkpointing {:,} unique addresses"
                                     .format(len(unique_addressess)))

                for x in set(unique_addressess):
                    credit = Decimal("0")
                    for entry in hyp.execute("SELECT amount,reward FROM transactions WHERE (recipient = ? AND block_height < ?);", (x[0],) + (depth_specific,)):
                        try:
                            credit = quantize_eight(credit) + quantize_eight(entry[0]) + quantize_eight(entry[1])
                            credit = 0 if credit is None else credit
                        except IndexError:
                            credit = 0

                    debit = Decimal("0")
                    for entry in hyp.execute("SELECT amount,fee FROM transactions WHERE (address = ? AND block_height < ?);", (x[0],) + (depth_specific,)):
                        try:
                            debit = quantize_eight(debit) + quantize_eight(entry[0]) + quantize_eight(entry[1])
                            debit = 0 if debit is None else debit
                        except IndexError:
                            debit = 0

                    end_balance = quantize_eight(credit - debit)

                    # self.app_log.info("Address: "+ str(x))
                    # app_log.info("Credit: " + str(credit))
                    # app_log.info("Debit: " + str(debit))
                    # app_log.info("Fees: " + str(fees))
                    # app_log.info("Rewards: " + str(rewards))
                    # self.app_log.info("Balance: " + str(end_balance))

                    # print(x[0],end_balance)

                    if end_balance > 0:
                        timestamp = str(time.time())
                        hyp.execute("INSERT INTO transactions VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (
                            depth_specific - 1, timestamp, "Hyperblock", x[0], str(end_balance), "0", "0", "0", "0",
                            "0", "0", "0"))
                hyper.commit()

                hyp.execute("DELETE FROM transactions WHERE block_height < ? AND address != 'Hyperblock';", (depth_specific,))
                hyper.commit()

                hyp.execute("DELETE FROM misc WHERE block_height < ?;", (depth_specific,))  # remove diff calc
                hyper.commit()

                hyp.execute("VACUUM")
                hyper.close()

                if os.path.exists(self.config.hyper_path_conf):
                    os.remove(self.config.hyper_path_conf)  # remove the old hyperblocks

                os.rename(self.config.ledger_path_conf + '.temp', self.config.hyper_path_conf)

            if self.config.full_ledger == 0 and os.path.exists(self.config.ledger_path_conf) and self.is_mainnet:
                os.remove(self.config.ledger_path_conf)
                self.app_log.warning("Removed full ledger and only kept hyperblocks")

        except Exception as e:
            raise ValueError("There was an issue converting to Hyperblocks: {}".format(e))

    def bootstrap(self):
        try:
            types = ['static/*.db-wal', 'static/*.db-shm']
            for t in types:
                for f in glob.glob(t):
                    os.remove(f)
                    print(f, "deleted")

            archive_path = self.config.ledger_path_conf + ".tar.gz"
            download_file("https://bismuth.cz/ledger.tar.gz", archive_path)

            with tarfile.open(archive_path) as tar:
                tar.extractall("static/")  # NOT COMPATIBLE WITH CUSTOM PATH CONFS

        except:
            self.app_log.warning("Something went wrong during bootstrapping, aborted")
            raise

    def check_integrity(self, database):
        # check ledger integrity
        with sqlite3.connect(database) as ledger_check:
            ledger_check.text_factory = str
            l = ledger_check.cursor()

            try:
                l.execute("PRAGMA table_info('transactions')")
                redownload = False
            except:
                redownload = True

            if len(l.fetchall()) != 12:
                self.app_log.warning(
                    "Status: Integrity check on database {} failed, bootstrapping from the website".format(database))
                redownload = True

        if redownload and self.is_mainnet:
            self.bootstrap()

    def balanceget(self, balance_address, c):
        # verify balance

        # app_log.info("Mempool: Verifying balance")
        # app_log.info("Mempool: Received address: " + str(balance_address))

        base_mempool = mp.MEMPOOL.fetchall("SELECT amount, openfield, operation FROM transactions WHERE address = ?;",
                                           (balance_address,))

        # include mempool fees

        debit_mempool = 0
        if base_mempool:
            for x in base_mempool:
                debit_tx = Decimal(x[0])
                fee = fee_calculate(x[1], x[2], self.last_block)
                debit_mempool = quantize_eight(debit_mempool + debit_tx + fee)
        else:
            debit_mempool = 0
        # include mempool fees

        credit_ledger = Decimal("0")
        for entry in self.execute_param(c, ("SELECT amount FROM transactions WHERE recipient = ?;"), (balance_address,)):
            try:
                credit_ledger = quantize_eight(credit_ledger) + quantize_eight(entry[0])
                credit_ledger = 0 if credit_ledger is None else credit_ledger
            except:
                credit_ledger = 0

        fees = Decimal("0")
        debit_ledger = Decimal("0")

        for entry in self.execute_param(c, ("SELECT fee, amount FROM transactions WHERE address = ?;"), (balance_address,)):
            try:
                fees = quantize_eight(fees) + quantize_eight(entry[0])
                fees = 0 if fees is None else fees
            except:
                fees = 0

            try:
                debit_ledger = debit_ledger + Decimal(entry[1])
                debit_ledger = 0 if debit_ledger is None else debit_ledger
            except:
                debit_ledger = 0

        debit = quantize_eight(debit_ledger + debit_mempool)

        rewards = Decimal("0")
        for entry in self.execute_param(c, ("SELECT reward FROM transactions WHERE recipient = ?;"), (balance_address,)):
            try:
                rewards = quantize_eight(rewards) + quantize_eight(entry[0])
                rewards = 0 if rewards is None else rewards
            except:
                rewards = 0

        balance = quantize_eight(credit_ledger - debit - fees + rewards)
        balance_no_mempool = float(credit_ledger) - float(debit_ledger) - float(fees) + float(rewards)
        # app_log.info("Mempool: Projected transction address balance: " + str(balance))
        return str(balance), str(credit_ledger), str(debit), str(fees), str(rewards), str(balance_no_mempool)

    def verify(self, h3):
        try:
            self.app_log.warning("Blockchain verification started...")
            # verify blockchain
            self.execute(h3, ("SELECT Count(*) FROM transactions"))
            db_rows = self.h3.fetchone()[0]
            self.app_log.warning("Total steps: {}".format(db_rows))

            # verify genesis
            if self.config.full_ledger:
                self.execute(h3, ("SELECT block_height, recipient FROM transactions WHERE block_height = 1"))
                result = self.h3.fetchall()[0]
                block_height = result[0]
                genesis = result[1]
                self.app_log.warning("Genesis: {}".format(genesis))
                if str(genesis) != self.config.genesis_conf and int(
                        block_height) == 0:  # change this line to your genesis address if you want to clone
                    self.app_log.warning("Invalid genesis address")
                    sys.exit(1)
            # verify genesis

            invalid = 0
            for row in self.execute(h3,
                               ('SELECT * FROM transactions WHERE block_height > 1 and reward = 0 ORDER BY block_height')):

                db_block_height = str(row[0])
                db_timestamp = '%.2f' % (quantize_two(row[1]))
                db_address = str(row[2])[:56]
                db_recipient = str(row[3])[:56]
                db_amount = '%.8f' % (quantize_eight(row[4]))
                db_signature_enc = str(row[5])[:684]
                db_public_key_hashed = str(row[6])[:1068]
                db_public_key = RSA.importKey(base64.b64decode(db_public_key_hashed))
                db_operation = str(row[10])[:30]
                db_openfield = str(row[11])  # no limit for backward compatibility

                db_transaction = (db_timestamp, db_address, db_recipient, db_amount, db_operation, db_openfield)

                db_signature_dec = base64.b64decode(db_signature_enc)
                verifier = PKCS1_v1_5.new(db_public_key)
                hash = SHA.new(str(db_transaction).encode("utf-8"))
                if verifier.verify(hash, db_signature_dec):
                    pass
                else:
                    self.app_log.warning("Signature validation problem: {} {}".format(db_block_height, db_transaction))
                    invalid = invalid + 1

            if invalid == 0:
                self.app_log.warning("All transacitons in the local ledger are valid")

        except Exception as e:
            self.app_log.warning("Error: {}".format(e))
            raise

    def blocknf(self, block_hash_delete, peer_ip, conn, c, hdd, h, hdd2, h2):
        my_time = time.time()

        if not self.db_lock.locked():
            self.db_lock.acquire()
            backup_data = None  # used in "finally" section
            skip = False
            reason = ""

            try:
                self.execute(c, 'SELECT * FROM transactions ORDER BY block_height DESC LIMIT 1')
                results = c.fetchone()
                db_block_height = results[0]
                db_block_hash = results[7]

                ip = {'ip': peer_ip}
                self.plugin_manager.execute_filter_hook('filter_rollback_ip', ip)
                if ip['ip'] == 'no':
                    reason = "Filter blocked this rollback"
                    skip = True

                elif db_block_height < 2:
                    reason = "Will not roll back this block"
                    skip = True

                elif db_block_hash != block_hash_delete:
                    # print db_block_hash
                    # print block_hash_delete
                    reason = "We moved away from the block to rollback, skipping"
                    skip = True

                else:
                    # backup

                    self.execute_param(c, "SELECT * FROM transactions WHERE block_height >= ?;", (db_block_height,))
                    backup_data = c.fetchall()
                    # this code continues at the bottom because of ledger presence check

                    # delete followups
                    self.execute_param(c, "DELETE FROM transactions WHERE block_height >= ? OR block_height <= ?",
                                  (db_block_height, -db_block_height))
                    self.commit(conn)

                    self.execute_param(c, "DELETE FROM misc WHERE block_height >= ?;", (str(db_block_height),))
                    self.commit(conn)

                    # execute_param(c, ('DELETE FROM transactions WHERE address = "Development Reward" AND block_height <= ?'), (-db_block_height,))
                    # self.commit(conn)

                    self.app_log.warning(
                        "Node {} didn't find block {}({}), rolled back".format(peer_ip, db_block_height, db_block_hash))

                    # roll back hdd too
                    if self.config.full_ledger:  # rollback ledger.db
                        self.execute_param(h, "DELETE FROM transactions WHERE block_height >= ? OR block_height <= ?",
                                      (db_block_height, -db_block_height))
                        self.commit(hdd)
                        self.execute_param(h, "DELETE FROM misc WHERE block_height >= ?;", (str(db_block_height),))
                        self.commit(hdd)

                    if self.config.ram_conf:  # rollback hyper.db
                        self.execute_param(h2, "DELETE FROM transactions WHERE block_height >= ? OR block_height <= ?",
                                      (db_block_height, -db_block_height))
                        self.commit(hdd2)
                        self.execute_param(h2, "DELETE FROM misc WHERE block_height >= ?;", (str(db_block_height),))
                        self.commit(hdd2)

                    self.hdd_block = int(db_block_height) - 1
                    # /roll back hdd too

                    # rollback indices
                    self.tokens_rollback(db_block_height, self.app_log)
                    self.aliases_rollback(db_block_height, self.app_log)
                    self.staking_rollback(db_block_height, self.app_log)
                    # /rollback indices

            except Exception as e:
                self.app_log.info(e)

            finally:
                self.db_lock.release()
                if skip:
                    rollback = {"timestamp": my_time, "height": db_block_height, "ip": peer_ip,
                                "hash": db_block_hash, "skipped": True, "reason": reason}
                    self.plugin_manager.execute_action_hook('rollback', rollback)
                    self.app_log.info("Skipping rollback: {}".format(reason))
                else:
                    try:
                        nb_tx = 0
                        for tx in backup_data:
                            tx_short = "{} - {} to {}: {} ({})".format(tx[1], tx[2], tx[3], tx[4], tx[11])
                            if tx[9] == 0:
                                try:
                                    nb_tx += 1
                                    self.app_log.info(
                                        mp.MEMPOOL.merge((tx[1], tx[2], tx[3], tx[4], tx[5], tx[6], tx[10], tx[11]),
                                                         peer_ip, c, False,
                                                         revert=True))  # will get stuck if you change it to respect db_lock
                                    self.app_log.warning("Moved tx back to mempool: {}".format(tx_short))
                                except Exception as e:
                                    self.app_log.warning("Error during moving tx back to mempool: {}".format(e))
                            else:
                                # It's the coinbase tx, so we get the miner address
                                miner = tx[3]
                                height = tx[0]
                        rollback = {"timestamp": my_time, "height": height, "ip": peer_ip, "miner": miner,
                                    "hash": db_block_hash, "tx_count": nb_tx, "skipped": False, "reason": ""}
                        self.plugin_manager.execute_action_hook('rollback', rollback)

                    except Exception as e:
                        self.app_log.warning("Error during moving txs back to mempool: {}".format(e))

        else:
            reason = "Skipping rollback, other ledger operation in progress"
            rollback = {"timestamp": my_time, "ip": peer_ip, "skipped": True, "reason": reason}
            self.plugin_manager.execute_action_hook('rollback', rollback)
            self.app_log.info(reason)

    def manager(self, c):
        # moved to peers_manager
        # reset_time = startup_time
        # peers_test("peers.txt")
        # peers_test("suggested_peers.txt")

        until_purge = 0

        while not self.IS_STOPPING:
            # dict_keys = peer_dict.keys()
            # random.shuffle(peer_dict.items())
            if until_purge == 0:
                # will purge once at start, then about every hour (120 * 30 sec)
                mp.MEMPOOL.purge()
                until_purge = 120

            until_purge -= 1

            # peer management
            if not self.is_regnet:
                # regnet never tries to connect
                self.peers.manager_loop(target=self.worker)

            self.app_log.warning("Status: Threads at {} / {}".format(threading.active_count(), self.config.thread_limit_conf))
            self.app_log.info("Status: Syncing nodes: {}".format(self.syncing))
            self.app_log.info("Status: Syncing nodes: {}/3".format(len(self.syncing)))

            # Status display for Peers related info
            self.peers.status_log()
            mp.MEMPOOL.status()

            # last block
            self.execute(c, "SELECT block_height, timestamp FROM transactions WHERE reward != 0 ORDER BY block_height DESC LIMIT 1;")  # or it takes the first
            result = c.fetchall()[0]
            self.last_block = result[0]
            last_block_ago = int(time.time() - result[1])
            self.app_log.warning("Status: Last block {} was generated {} minutes ago".format(self.last_block, '%.2f' % (last_block_ago / 60)))
            # last block
            # status Hook
            uptime = int(time.time() - self.startup_time)
            tempdiff = self.difficulty(c)  # Can we avoid recalc that ?
            status = {"protocolversion": self.config.version_conf,
                      "walletversion": self.VERSION,
                      "testnet": self.is_testnet,
                      # config data
                      "blocks": self.last_block,
                      "timeoffset": 0,
                      "connections": self.peers.consensus_size,
                      "difficulty": tempdiff[0],  # live status, bitcoind format
                      "threads": threading.active_count(),
                      "uptime": uptime,
                      "consensus": self.peers.consensus,
                      "consensus_percent": self.peers.consensus_percentage,
                      "last_block_ago": last_block_ago}  # extra data
            if self.is_regnet:
                status['regnet']= True
            self.plugin_manager.execute_action_hook('status', status)
            # end status hook

            if self.peerlist: #if it is not empty
                try:
                    self.peers.peers_dump(self.peerlist, self.peers.peer_dict)
                except Exception as e:
                    self.app_log.warning("There was an issue saving peers ({}), skipped".format(e))


            # app_log.info(threading.enumerate() all threads)
            for i in range(30):
                # faster stop
                if not self.IS_STOPPING:
                    time.sleep(1)

    def ledger_balance3(self, address, c, cache):
        # Many heavy blocks are pool payouts, same address.
        # Cache pre_balance instead of recalc for every tx
        if address in cache:
            return cache[address]
        credit_ledger = Decimal(0)
        for entry in self.execute_param(c, "SELECT amount, reward FROM transactions WHERE recipient = ?;", (address,)):
            credit_ledger += quantize_eight(entry[0]) + quantize_eight(entry[1])

        debit_ledger = Decimal(0)
        for entry in self.execute_param(c, "SELECT amount, fee FROM transactions WHERE address = ?;", (address,)):
            debit_ledger += quantize_eight(entry[0]) + quantize_eight(entry[1])

        cache[address] = quantize_eight(credit_ledger - debit_ledger)
        return cache[address]


    def digest_block(self, data, sdef, peer_ip, conn, c, hdd, h, hdd2, h2, h3, index, index_cursor):
        block_height_new = self.last_block + 1  # for logging purposes.
        block_hash = 'N/A'
        failed_cause = ''
        block_count = 0
        tx_count = 0

        if self.peers.is_banned(peer_ip):
            # no need to loose any time with banned peers
            raise ValueError("Cannot accept blocks from a banned peer")
            # since we raise, it will also drop the connection, it's fine since he's banned.

        if not self.db_lock.locked():
            self.db_lock.acquire()

            while mp.MEMPOOL.lock.locked():
                time.sleep(0.1)
                self.app_log.info("Block: Waiting for mempool to unlock {}".format(peer_ip))

            self.app_log.warning("Block: Digesting started from {}".format(peer_ip))
            # variables that have been quantized are prefixed by q_ So we can avoid any unnecessary quantize again later. Takes time.
            # Variables that are only used as quantized decimal are quantized once and for all.

            block_size = Decimal(sys.getsizeof(str(data))) / Decimal(1000000)
            self.app_log.warning("Block: size: {} MB".format(block_size))

            q_time_now = quantize_two(time.time())
            try:
                block_list = data

                # reject block with duplicate transactions
                signature_list = []
                block_transactions = []

                for transaction_list in block_list:
                    block_count += 1

                    # Reworked process: we exit as soon as we find an error, no need to process further tests.
                    # Then the exception handler takes place.

                    # TODO EGG: benchmark this loop vs a single "WHERE IN" SQL
                    # move down, so bad format tx do not require sql query
                    for entry in transaction_list:  # sig 4
                        tx_count += 1
                        entry_signature = entry[4]
                        if entry_signature:  # prevent empty signature database retry hack
                            signature_list.append(entry_signature)
                            # reject block with transactions which are already in the ledger ram
                            self.execute_param(h3, "SELECT block_height FROM transactions WHERE signature = ?;",
                                          (entry_signature,))
                            test = h3.fetchone()
                            if test:
                                # print(last_block)
                                raise ValueError("That transaction {} is already in our ram ledger, block_height {}".format(
                                    entry_signature[:10], test[0]))

                            self.execute_param(c, "SELECT block_height FROM transactions WHERE signature = ?;",
                                          (entry_signature,))
                            test = c.fetchone()
                            if test:
                                # print(last_block)
                                raise ValueError("That transaction {} is already in our ledger, block_height {}".format(
                                    entry_signature[:10], test[0]))
                        else:
                            raise ValueError("Empty signature from {}".format(peer_ip))

                    tx_count = len(signature_list)
                    if tx_count != len(set(signature_list)):
                        raise ValueError("There are duplicate transactions in this block, rejected")

                    del signature_list[:]

                    # previous block info
                    self.execute(c, "SELECT block_hash, block_height, timestamp FROM transactions WHERE reward != 0 ORDER BY block_height DESC LIMIT 1;")
                    result = c.fetchall()
                    db_block_hash = result[0][0]
                    db_block_height = result[0][1]
                    q_db_timestamp_last = quantize_two(result[0][2])
                    block_height_new = db_block_height + 1
                    # previous block info

                    transaction_list_converted = []  # makes sure all the data are properly converted as in the previous lines
                    for tx_index, transaction in enumerate(transaction_list):
                        # verify signatures
                        q_received_timestamp = quantize_two(transaction[0])  # we use this several times
                        received_timestamp = '%.2f' % q_received_timestamp
                        received_address = str(transaction[1])[:56]
                        received_recipient = str(transaction[2])[:56]
                        received_amount = '%.8f' % (quantize_eight(transaction[3]))
                        received_signature_enc = str(transaction[4])[:684]
                        received_public_key_hashed = str(transaction[5])[:1068]
                        received_operation = str(transaction[6])[:30]
                        received_openfield = str(transaction[7])[:100000]

                        # if transaction == transaction_list[-1]:
                        if tx_index == tx_count - 1:  # faster than comparing the whole tx
                            # recognize the last transaction as the mining reward transaction
                            q_block_timestamp = q_received_timestamp
                            nonce = received_openfield[:128]
                            miner_address = received_address

                        transaction_list_converted.append((received_timestamp, received_address, received_recipient,
                                                           received_amount, received_signature_enc,
                                                           received_public_key_hashed, received_operation,
                                                           received_openfield))

                        # if (q_time_now < q_received_timestamp + 432000) or not quicksync:

                        # convert readable key to instance
                        received_public_key = RSA.importKey(base64.b64decode(received_public_key_hashed))

                        received_signature_dec = base64.b64decode(received_signature_enc)
                        verifier = PKCS1_v1_5.new(received_public_key)

                        validate_pem(received_public_key_hashed)

                        hash = SHA.new(str((received_timestamp, received_address, received_recipient, received_amount,
                                            received_operation, received_openfield)).encode("utf-8"))
                        if not verifier.verify(hash, received_signature_dec):
                            raise ValueError("Invalid signature from {}".format(received_address))
                        else:
                            self.app_log.info("Valid signature from {} to {} amount {}".format(received_address,
                                                                                          received_recipient,
                                                                                          received_amount))
                        if float(received_amount) < 0:
                            raise ValueError("Negative balance spend attempt")

                        if received_address != hashlib.sha224(base64.b64decode(received_public_key_hashed)).hexdigest():
                            raise ValueError("Attempt to spend from a wrong address")

                        if not essentials.address_validate(received_address):
                            raise ValueError("Not a valid sender address")

                        if not essentials.address_validate(received_recipient):
                            raise ValueError("Not a valid recipient address")

                        if q_time_now < q_received_timestamp:
                            raise ValueError(
                                "Future transaction not allowed, timestamp {} minutes in the future".format(
                                    quantize_two((q_received_timestamp - q_time_now) / 60)))
                        if q_db_timestamp_last - 86400 > q_received_timestamp:
                            raise ValueError("Transaction older than 24h not allowed.")
                            # verify signatures
                            # else:
                            # print("hyp1")

                    # reject blocks older than latest block
                    if q_block_timestamp <= q_db_timestamp_last:
                        raise ValueError("Block is older than the previous one, will be rejected")

                    # calculate current difficulty
                    diff = self.difficulty(c)

                    self.app_log.warning("Time to generate block {}: {:.2f}".format(db_block_height + 1, diff[2]))
                    self.app_log.warning("Current difficulty: {}".format(diff[3]))
                    self.app_log.warning("Current blocktime: {}".format(diff[4]))
                    self.app_log.warning("Current hashrate: {}".format(diff[5]))
                    self.app_log.warning("New difficulty after adjustment: {}".format(diff[6]))
                    self.app_log.warning("Difficulty: {} {}".format(diff[0], diff[1]))

                    # app_log.info("Transaction list: {}".format(transaction_list_converted))
                    block_hash = hashlib.sha224(
                        (str(transaction_list_converted) + db_block_hash).encode("utf-8")).hexdigest()
                    # app_log.info("Last block hash: {}".format(db_block_hash))
                    self.app_log.info("Calculated block hash: {}".format(block_hash))
                    # app_log.info("Nonce: {}".format(nonce))

                    # check if we already have the hash
                    self.execute_param(h3, "SELECT block_height FROM transactions WHERE block_hash = ?", (block_hash,))
                    dummy = c.fetchone()
                    if dummy:
                        raise ValueError("Skipping digestion of block {} from {}, because we already have it on block_height {}".
                                         format(block_hash[:10], peer_ip, dummy[0]))

                    if self.is_mainnet:
                        if block_height_new < self.POW_FORK:
                            diff_save = mining.check_block(block_height_new, miner_address, nonce, db_block_hash, diff[0],
                                                           received_timestamp, q_received_timestamp, q_db_timestamp_last,
                                                           peer_ip=peer_ip, app_log=self.app_log)
                        else:
                            diff_save = mining_heavy3.check_block(block_height_new, miner_address, nonce, db_block_hash, diff[0],
                                                                  received_timestamp, q_received_timestamp, q_db_timestamp_last,
                                                                  peer_ip=peer_ip, app_log=self.app_log)
                    elif self.is_testnet:
                        diff_save = mining_heavy3.check_block(block_height_new, miner_address, nonce, db_block_hash,
                                                              diff[0],
                                                              received_timestamp, q_received_timestamp, q_db_timestamp_last,
                                                              peer_ip=peer_ip, app_log=self.app_log)
                    else:
                        # it's regnet then, will use a specific fake method here.
                        diff_save = mining_heavy3.check_block(block_height_new, miner_address, nonce, db_block_hash,
                                                              regnet.REGNET_DIFF,
                                                              received_timestamp, q_received_timestamp, q_db_timestamp_last,
                                                              peer_ip=peer_ip, app_log=self.app_log)

                    fees_block = []
                    mining_reward = 0  # avoid warning

                    # Cache for multiple tx from same address
                    balances = {}
                    for tx_index, transaction in enumerate(transaction_list):
                        db_timestamp = '%.2f' % quantize_two(transaction[0])
                        db_address = str(transaction[1])[:56]
                        db_recipient = str(transaction[2])[:56]
                        db_amount = '%.8f' % quantize_eight(transaction[3])
                        db_signature = str(transaction[4])[:684]
                        db_public_key_hashed = str(transaction[5])[:1068]
                        db_operation = str(transaction[6])[:30]
                        db_openfield = str(transaction[7])[:100000]

                        block_debit_address = 0
                        block_fees_address = 0

                        # this also is redundant on many tx per address block
                        for x in transaction_list:
                            if x[1] == db_address:  # make calculation relevant to a particular address in the block
                                block_debit_address = quantize_eight(Decimal(block_debit_address) + Decimal(x[3]))

                                if x != transaction_list[-1]:
                                    block_fees_address = quantize_eight(Decimal(block_fees_address) + Decimal(
                                        fee_calculate(db_openfield, db_operation,
                                                      self.last_block)))  # exclude the mining tx from fees

                        # print("block_fees_address", block_fees_address, "for", db_address)
                        # app_log.info("Digest: Inbound block credit: " + str(block_credit))
                        # app_log.info("Digest: Inbound block debit: " + str(block_debit))
                        # include the new block

                        # if (q_time_now < q_received_timestamp + 432000) and not quicksync:
                        # balance_pre = quantize_eight(credit_ledger - debit_ledger - fees + rewards)  # without projection
                        balance_pre = self.ledger_balance3(db_address, c, balances) #keep this as c (ram hyperblock access)

                        # balance = quantize_eight(credit - debit - fees + rewards)
                        balance = quantize_eight(balance_pre - block_debit_address)
                        # app_log.info("Digest: Projected transaction address balance: " + str(balance))
                        # else:
                        #    print("hyp2")

                        fee = fee_calculate(db_openfield, db_operation, self.last_block)

                        fees_block.append(quantize_eight(fee))
                        # app_log.info("Fee: " + str(fee))

                        # decide reward
                        if tx_index == tx_count - 1:
                            db_amount = 0  # prevent spending from another address, because mining txs allow delegation
                            if db_block_height <= 10000000:
                                mining_reward = 15 - (quantize_eight(block_height_new) / quantize_eight(1000000 / 2)) - Decimal("0.8")
                                if mining_reward < 0:
                                    mining_reward = 0
                            else:
                                mining_reward = 0

                            reward = quantize_eight(mining_reward + sum(fees_block[:-1]))
                            # don't request a fee for mined block so new accounts can mine
                            fee = 0
                        else:
                            reward = 0

                        if quantize_eight(balance_pre) < quantize_eight(db_amount):
                            raise ValueError("{} sending more than owned: {}/{}".format(db_address, db_amount, balance_pre))

                        if quantize_eight(balance) - quantize_eight(block_fees_address) < 0:
                            # exclude fee check for the mining/header tx
                            raise ValueError("{} Cannot afford to pay fees".format(db_address))

                        # append, but do not insert to ledger before whole block is validated, note that it takes already validated values (decimals, length)
                        self.app_log.info("Block: Appending transaction back to block with {} transactions in it".format(
                            len(block_transactions)))
                        block_transactions.append((block_height_new, db_timestamp, db_address, db_recipient, db_amount,
                                                   db_signature, db_public_key_hashed, block_hash, fee, reward,
                                                   db_operation, db_openfield))

                        try:
                            mp.MEMPOOL.delete_transaction(db_signature)
                            self.app_log.info("Block: Removed processed transaction {} from the mempool while digesting".format(
                                db_signature[:56]))
                        except:
                            # tx was not or is no more in the local mempool
                            pass
                    # end for transaction_list

                    # save current diff (before the new block)
                    self.execute_param(c, "INSERT INTO misc VALUES (?, ?)", (block_height_new, diff_save))
                    self.commit(conn)

                    # quantized vars have to be converted, since Decimal is not json serializable...
                    self.plugin_manager.execute_action_hook('block',
                                                       {'height': block_height_new, 'diff': diff_save,
                                                        'hash': block_hash, 'timestamp': float(q_block_timestamp),
                                                        'miner': miner_address, 'ip': peer_ip})

                    self.plugin_manager.execute_action_hook('fullblock',
                                                       {'height': block_height_new, 'diff': diff_save,
                                                        'hash': block_hash, 'timestamp': float(q_block_timestamp),
                                                        'miner': miner_address, 'ip': peer_ip,
                                                        'transactions': block_transactions})

                    # do not use "transaction" as it masks upper level variable.
                    for transaction2 in block_transactions:
                        self.execute_param(c, "INSERT INTO transactions VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (
                            str(transaction2[0]), str(transaction2[1]),
                            str(transaction2[2]), str(transaction2[3]),
                            str(transaction2[4]), str(transaction2[5]),
                            str(transaction2[6]), str(transaction2[7]),
                            str(transaction2[8]), str(transaction2[9]),
                            str(transaction2[10]), str(transaction2[11])))
                        # secure commit for slow nodes
                        self.commit(conn)

                    # savings
                    if self.is_testnet or block_height_new >= 843000:
                        # no savings for regnet
                        if int(block_height_new) % 10000 == 0:  # every x blocks
                            staking.staking_update(conn, c, index, index_cursor, "normal", block_height_new, self.app_log)
                            staking.staking_payout(conn, c, index, index_cursor, block_height_new, float(q_block_timestamp), self.app_log)
                            staking.staking_revalidate(conn, c, index, index_cursor, block_height_new, self.app_log)

                    # new hash
                    c.execute("SELECT * FROM transactions WHERE block_height = (SELECT max(block_height) FROM transactions)")
                    # Was trying to simplify, but it's the latest mirror hash. not the latest block, nor the mirror of the latest block.
                    # c.execute("SELECT * FROM transactions WHERE block_height = ?", (block_height_new -1,))
                    tx_list_to_hash = c.fetchall()
                    mirror_hash = blake2b(str(tx_list_to_hash).encode(), digest_size=20).hexdigest()
                    # /new hash

                    # dev reward
                    if int(block_height_new) % 10 == 0:  # every 10 blocks
                        self.execute_param(c, "INSERT INTO transactions VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                                      (-block_height_new, str(q_time_now), "Development Reward", str(self.config.genesis_conf),
                                       str(mining_reward), "0", "0", mirror_hash, "0", "0", "0", "0"))
                        self.commit(conn)

                        self.execute_param(c, "INSERT INTO transactions VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                                      (-block_height_new, str(q_time_now), "Hypernode Payouts",
                                       "3e08b5538a4509d9daa99e01ca5912cda3e98a7f79ca01248c2bde16",
                                       "8", "0", "0", mirror_hash, "0", "0", "0", "0"))
                        self.commit(conn)
                    # /dev reward

                    # app_log.warning("Block: {}: {} valid and saved from {}".format(block_height_new, block_hash[:10], peer_ip))
                    self.app_log.warning(
                        "Valid block: {}: {} digestion from {} completed in {}s.".format(block_height_new, block_hash[:10],
                                                                                         peer_ip,
                                                                                         str(time.time() - float(q_time_now))[:5]))

                    del block_transactions[:]
                    self.peers.unban(peer_ip)

                    # This new block may change the int(diff). Trigger the hook whether it changed or not.
                    diff = self.difficulty(c)
                    self.plugin_manager.execute_action_hook('diff', diff[0])
                    # We could recalc diff after inserting block, and then only trigger the block hook, but I fear this would delay the new block event.

                    # /whole block validation
                    # NEW: returns new block hash
                    return block_hash

            except Exception as e:
                self.app_log.warning("Block: processing failed", exc_info=True)
                failed_cause = str(e)
                # Temp

                # exc_type, exc_obj, exc_tb = sys.exc_info()
                # fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                # print(exc_type, fname, exc_tb.tb_lineno)

                if self.peers.warning(sdef, peer_ip, "Rejected block", 2):
                    raise ValueError("{} banned".format(peer_ip))
                raise ValueError("Block: digestion aborted")

            finally:
                if self.config.full_ledger or self.config.ram_conf:
                    # first case move stuff from hyper.db to ledger.db; second case move stuff from ram to both
                    self.db_to_drive(hdd, h, hdd2, h2)
                self.db_lock.release()
                # TODO: q_time_now is sometimes undefined, causing this hook to fail
                delta_t = time.time() - float(q_time_now)
                # app_log.warning("Block: {}: {} digestion completed in {}s.".format(block_height_new,  block_hash[:10], delta_t))
                self.plugin_manager.execute_action_hook('digestblock',
                                                   {'failed': failed_cause, 'ip': peer_ip, 'deltat': delta_t,
                                                    "blocks": block_count, "txs": tx_count})

        else:
            self.app_log.warning("Block: Skipping processing from {}, someone delivered data faster".format(peer_ip))
            self.plugin_manager.execute_action_hook('digestblock', {'failed': "skipped", 'ip': peer_ip})


    def coherence_check(self):
        try:
            with open("coherence_last", 'r') as filename:
                coherence_last = int(filename.read())

        except:
            self.app_log.warning("Coherence anchor not found, going through the whole chain")
            coherence_last = 0

        self.app_log.warning("Status: Testing chain coherence, starting with block {}".format(coherence_last))

        # Check only the ledgers we're currently recording
        if self.config.full_ledger:
            chains_to_check = [self.config.ledger_path_conf, self.config.hyper_path_conf]
        else:
            chains_to_check = [self.config.hyper_path_conf]

        for chain in chains_to_check:
            self.conn = sqlite3.connect(chain)
            self.c = self.conn.cursor()

            # perform test on transaction table
            y = None
            # Egg: not sure block_height != (0 OR 1)  gives the proper result, 0 or 1  = 1. not in (0, 1) could be better.
            for row in self.c.execute("SELECT block_height FROM transactions WHERE reward != 0 AND block_height != (0 OR 1) AND block_height >= ? ORDER BY block_height ASC", (coherence_last,)):
                y_init = row[0]

                if y is None:
                    y = y_init

                if row[0] != y:

                    for chain2 in chains_to_check:
                        conn2 = sqlite3.connect(chain2)
                        c2 = conn2.cursor()
                        self.app_log.warning("Status: Chain {} transaction coherence error at: {}. {} instead of {}".format(chain, row[0] - 1, row[0], y))
                        c2.execute("DELETE FROM transactions WHERE block_height >= ? OR block_height <= ?", (row[0] - 1, -(row[0] + 1)))
                        conn2.commit()
                        c2.execute("DELETE FROM misc WHERE block_height >= ?", (row[0] - 1,))
                        conn2.commit()

                        # execute_param(conn2, ('DELETE FROM transactions WHERE address = "Development Reward" AND block_height <= ?'), (-(row[0]+1),))
                        # self.commit(conn2)
                        # conn2.close()

                        # rollback indices
                        self.tokens_rollback(y, self.app_log)
                        self.aliases_rollback(y, self.app_log)
                        self.staking_rollback(y, self.app_log)

                        # rollback indices

                        self.app_log.warning("Status: Due to a coherence issue at block {}, {} has been rolled back and will be resynchronized".format(y, chain))
                    break

                y = y + 1

            # perform test on misc table
            y = None

            for row in self.c.execute("SELECT block_height FROM misc WHERE block_height > ? ORDER BY block_height ASC", (300000,)):
                y_init = row[0]

                if y is None:
                    y = y_init
                    # print("assigned")
                    # print(row[0], y)

                if row[0] != y:
                    # print(row[0], y)
                    for chain2 in chains_to_check:
                        conn2 = sqlite3.connect(chain2)
                        c2 = conn2.cursor()
                        self.app_log.warning("Status: Chain {} difficulty coherence error at: {} {} instead of {}".format(chain, row[0] - 1, row[0], y))
                        c2.execute("DELETE FROM transactions WHERE block_height >= ?", (row[0] - 1,))
                        conn2.commit()
                        c2.execute("DELETE FROM misc WHERE block_height >= ?", (row[0] - 1,))
                        conn2.commit()

                        self.execute_param(conn2, ('DELETE FROM transactions WHERE address = "Development Reward" AND block_height <= ?'), (-(row[0] + 1),))
                        self.commit(conn2)
                        conn2.close()

                        # rollback indices
                        self.tokens_rollback(y, self.app_log)
                        self.aliases_rollback(y, self.app_log)
                        self.staking_rollback(y, self.app_log)
                        # rollback indices

                        self.app_log.warning("Status: Due to a coherence issue at block {}, {} has been rolled back and will be resynchronized".format(y, chain))
                    break

                y = y + 1

            self.app_log.warning("Status: Chain coherence test complete for {}".format(chain))
            self.conn.close()

            with open("coherence_last", 'w') as filename:
                filename.write(str(y - 1000))  # room for rollbacks

    def db_maintenance(self, conn):
        # db maintenance
        self.app_log.warning("Status: Database maintenance started")
        self.execute(conn, "VACUUM")
        mp.MEMPOOL.vacuum()
        self.app_log.warning("Status: Database maintenance finished")


    def ensure_good_peer_version(self, peer_ip):
        """
        cleanup after HF, kepts here for future use.
        """
        """
        # If we are post fork, but we don't know the version, then it was an old connection, close.
        if is_mainnet and (last_block >= POW_FORK) :
            if peer_ip not in peers.ip_to_mainnet:
                raise ValueError("Outbound: disconnecting old node {}".format(peer_ip));
            elif peers.ip_to_mainnet[peer_ip] not in version_allow:
                raise ValueError("Outbound: disconnecting old node {} - {}".format(peer_ip, peers.ip_to_mainnet[peer_ip]));
        """
        return True

    # client thread
    # if you "return" from the function, the exception code will node be executed and client thread will hang
    def worker(self, HOST, PORT):
        if self.IS_STOPPING:
            return
        dict_ip = {'ip': HOST}
        self.plugin_manager.execute_filter_hook('peer_ip', dict_ip)
        if self.peers.is_banned(HOST) or dict_ip['ip'] == 'banned':
            self.app_log.warning("IP {} is banned, won't connect".format(HOST))
            return

        timeout_operation = 60  # timeout
        timer_operation = time.time()  # start counting

        try:
            this_client = (HOST + ":" + str(PORT))
            s = socks.socksocket()
            if self.config.tor_conf:
                s.setproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 9050)
            # s.setblocking(0)
            s.connect((HOST, PORT))
            self.app_log.info("Outbound: Connected to {}".format(this_client))

            # communication starter

            send(s, "version")
            send(s, self.config.version)

            data = receive(s)

            if data == "ok":
                self.app_log.info("Outbound: Node protocol version of {} matches our client".format(this_client))
            else:
                raise ValueError("Outbound: Node protocol version of {} mismatch".format(this_client))

            # If we are post pow fork, then the peer has getversion command
            #if last_block >= POW_FORK - FORK_AHEAD:
            # Peers that are not up to date will disconnect since they don't know that command.
            # That is precisely what we need :D
            send(s, "getversion")
            peer_version = receive(s)
            if peer_version not in self.config.version_allow:
                raise ValueError("Outbound: Incompatible peer version {} from {}".format(peer_version, this_client))

            send(s, "hello")

            # communication starter

        except Exception as e:
            self.app_log.info("Could not connect to {}: {}".format(this_client, e))
            return  # can return here, because no lists are affected yet

        banned = False
        # if last_block >= POW_FORK - FORK_AHEAD:
        self.peers.store_mainnet(HOST, peer_version)
        try:
            peer_ip = s.getpeername()[0]
        except:
            # Should not happen, extra safety
            self.app_log.warning("Outbound: Transport endpoint was not connected");
            return

        if this_client not in self.peers.connection_pool:
            self.peers.append_client(this_client)
            self.app_log.info("Connected to {}".format(this_client))
            self.app_log.info("Current active pool: {}".format(self.peers.connection_pool))

        while not banned and self.peers.version_allowed(HOST, self.config.version_allow) and not self.IS_STOPPING:
            try:
                self.ensure_good_peer_version(HOST)

                hdd2, h2 = self.db_h2_define()
                conn, c = self.db_c_define()

                if self.config.full_ledger:
                    hdd, h = self.db_h_define()
                    h3 = h
                else:
                    hdd, h = None, None
                    h3 = h2

                index, index_cursor = self.index_define()

                data = receive(s)  # receive data, one and the only root point
                # print(data)

                if data == "peers":
                    subdata = receive(s)
                    self.peers.peersync(subdata)

                elif data == "sync":
                    if not time.time() <= timer_operation + timeout_operation:
                        timer_operation = time.time()  # reset timer

                    try:

                        global syncing

                        while len(self.syncing) >= 3:
                            if self.IS_STOPPING:
                                return
                            time.sleep(int(self.config.pause_conf))

                        self.syncing.append(peer_ip)
                        # sync start

                        # send block height, receive block height
                        send(s, "blockheight")

                        self.execute(c, ('SELECT max(block_height) FROM transactions'))
                        db_block_height = c.fetchone()[0]

                        self.app_log.info("Outbound: Sending block height to compare: {}".format(db_block_height))
                        # append zeroes to get static length
                        send(s, db_block_height)

                        received_block_height = receive(s)  # receive node's block height
                        self.app_log.info("Outbound: Node {} is at block height: {}".format(peer_ip, received_block_height))

                        if int(received_block_height) < db_block_height:
                            self.app_log.warning("Outbound: We have a higher block ({}) than {} ({}), sending".format(db_block_height, peer_ip, received_block_height))

                            data = receive(s)  # receive client's last block_hash

                            # send all our followup hashes
                            self.app_log.info("Outbound: Will seek the following block: {}".format(data))

                            # consensus pool 2 (active connection)
                            consensus_blockheight = int(received_block_height)  # str int to remove leading zeros
                            self.peers.consensus_add(peer_ip, consensus_blockheight, s, self.last_block)
                            # consensus pool 2 (active connection)

                            try:
                                self.execute_param(h3, ("SELECT block_height FROM transactions WHERE block_hash = ?;"), (data,))
                                client_block = h3.fetchone()[0]

                                self.app_log.info("Outbound: Node is at block {}".format(client_block))  # now check if we have any newer

                                self.execute(h3, ('SELECT block_hash FROM transactions ORDER BY block_height DESC LIMIT 1'))
                                db_block_hash = h3.fetchone()[0]  # get latest block_hash

                                if db_block_hash == data or not self.config.egress:
                                    if not self.config.egress:
                                        self.app_log.warning("Outbound: Egress disabled for {}".format(peer_ip))
                                        time.sleep(int(self.config.pause_conf))  # reduce CPU usage
                                    else:
                                        self.app_log.info("Outbound: Node {} has the latest block".format(peer_ip))
                                    send(s, "nonewblk")

                                else:
                                    blocks_fetched = []
                                    while len(str(blocks_fetched)) < 500000:  # limited size based on txs in blocks
                                        # execute_param(h3, ("SELECT block_height, timestamp,address,recipient,amount,signature,public_key,keep,openfield FROM transactions WHERE block_height > ? AND block_height <= ?;"),(str(int(client_block)),) + (str(int(client_block + 1)),))
                                        self.execute_param(h3, (
                                            "SELECT timestamp,address,recipient,amount,signature,public_key,cast(operation as TEXT),openfield FROM transactions WHERE block_height > ? AND block_height <= ?;"),
                                                      (str(int(client_block)), str(int(client_block + 1)),))
                                        result = h3.fetchall()
                                        if not result:
                                            break
                                        blocks_fetched.extend([result])
                                        client_block = int(client_block) + 1

                                    # blocks_send = [[l[1:] for l in group] for _, group in groupby(blocks_fetched, key=itemgetter(0))]  # remove block number

                                    self.app_log.info("Outbound: Selected {}".format(blocks_fetched))

                                    send(s, "blocksfnd")

                                    confirmation = receive(s)

                                    if confirmation == "blockscf":
                                        self.app_log.info("Outbound: Client confirmed they want to sync from us")
                                        send(s, blocks_fetched)

                                    elif confirmation == "blocksrj":
                                        self.app_log.info("Outbound: Client rejected to sync from us because we're dont have the latest block")

                            except Exception as e:
                                self.app_log.warning("Outbound: Block {} of {} not found".format(data[:8], peer_ip))
                                send(s, "blocknf")
                                send(s, data)

                        elif int(received_block_height) >= db_block_height:
                            if int(received_block_height) == db_block_height:
                                self.app_log.info("Outbound: We have the same block as {} ({}), hash will be verified".format(peer_ip, received_block_height))
                            else:
                                self.app_log.warning(
                                    "Outbound: We have a lower block ({}) than {} ({}), hash will be verified".format(
                                        db_block_height, peer_ip, received_block_height))

                            self.execute(c, ('SELECT block_hash FROM transactions ORDER BY block_height DESC LIMIT 1'))
                            db_block_hash = c.fetchone()[0]  # get latest block_hash

                            self.app_log.info("Outbound: block_hash to send: {}".format(db_block_hash))
                            send(s, db_block_hash)

                            self.ensure_good_peer_version(HOST)

                            # consensus pool 2 (active connection)
                            consensus_blockheight = int(received_block_height)  # str int to remove leading zeros
                            self.peers.consensus_add(peer_ip, consensus_blockheight, s, self.last_block)
                            # consensus pool 2 (active connection)

                    except Exception as e:
                        self.app_log.info("Outbound: Sync failed {}".format(e))
                    finally:
                        self.syncing.remove(peer_ip)

                elif data == "blocknf":  # one of the possible outcomes
                    block_hash_delete = receive(s)
                    # print peer_ip
                    # if max(consensus_blockheight_list) == int(received_block_height):
                    if int(received_block_height) == self.peers.consensus_max:
                        self.blocknf(block_hash_delete, peer_ip, conn, c, hdd, h, hdd2, h2)
                        if self.peers.warning(s, peer_ip, "Rollback", 2):
                            raise ValueError("{} is banned".format(peer_ip))

                    self.sendsync(s, peer_ip, "Block not found", False)

                elif data == "blocksfnd":
                    self.app_log.info("Outbound: Node {} has the block(s)".format(peer_ip))  # node should start sending txs in this step

                    # self.app_log.info("Inbound: Combined segments: " + segments)
                    # print peer_ip
                    if self.db_lock.locked():
                        self.app_log.warning("Skipping sync from {}, syncing already in progress".format(peer_ip))

                    else:
                        self.execute(c, "SELECT timestamp FROM transactions WHERE reward != 0 ORDER BY block_height DESC LIMIT 1;")  # or it takes the first
                        last_block_ago = Decimal(c.fetchone()[0])

                        if int(last_block_ago) < (time.time() - 600):
                            block_req = self.peers.consensus_most_common
                            self.app_log.warning("Most common block rule triggered")

                        else:
                            block_req = self.peers.consensus_max
                            self.app_log.warning("Longest chain rule triggered")

                        self.ensure_good_peer_version(HOST)

                        if int(received_block_height) >= block_req:
                            try:  # they claim to have the longest chain, things must go smooth or ban
                                self.app_log.warning("Confirming to sync from {}".format(peer_ip))

                                send(s, "blockscf")
                                segments = receive(s)
                                self.ensure_good_peer_version(HOST)

                            except:
                                if self.peers.warning(s, peer_ip, "Failed to deliver the longest chain", 2):
                                    raise ValueError("{} is banned".format(peer_ip))

                            else:
                                self.digest_block(segments, s, peer_ip, conn, c, hdd, h, hdd2, h2, h3, index, index_cursor)

                                # receive theirs
                        else:
                            send(s, "blocksrj")
                            self.app_log.warning("Inbound: Distant peer {} is at {}, should be at least {}".format(peer_ip, received_block_height, block_req))

                    self.sendsync(s, peer_ip, "Block found", True)

                    # block_hash validation end

                elif data == "nonewblk":
                    # send and receive mempool
                    if mp.MEMPOOL.sendable(peer_ip):
                        mempool_txs = mp.MEMPOOL.tx_to_send(peer_ip)
                        # self.app_log.info("Outbound: Extracted from the mempool: " + str(mempool_txs))  # improve: sync based on signatures only
                        # if len(mempool_txs) > 0: #wont sync mempool until we send something, which is bad
                        # send own
                        send(s, "mempool")
                        send(s, mempool_txs)
                        # send own
                        # receive theirs
                        segments = receive(s)
                        self.app_log.info(mp.MEMPOOL.merge(segments, peer_ip, c, True))
                        # receive theirs
                        # Tell the mempool we just send our pool to a peer
                        mp.MEMPOOL.sent(peer_ip)
                    self.sendsync(s, peer_ip, "No new block", True)

                else:
                    if data == '*':
                        raise ValueError("Broken pipe")
                    raise ValueError("Unexpected error, received: {}".format(str(data)[:32]))

            except Exception as e:
                """
                exc_type, exc_obj, exc_tb = sys.exc_info()
                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                print(exc_type, fname, exc_tb.tb_lineno)
                """
                # remove from active pool
                if this_client in self.peers.connection_pool:
                    self.app_log.info("Will remove {} from active pool {}".format(this_client, self.peers.connection_pool))
                    self.app_log.warning("Outbound: Disconnected from {}: {}".format(this_client, e))

                    self.peers.remove_client(this_client)

                # remove from active pool

                # remove from consensus 2
                try:
                    self.peers.consensus_remove(peer_ip)
                except:
                    pass
                # remove from consensus 2

                self.app_log.info("Connection to {} terminated due to {}".format(this_client, e))
                self.app_log.info("---thread {} ended---".format(threading.currentThread()))

                # properly end the connection
                if s:
                    s.close()
                # properly end the connection
                if self.config.debug_conf:
                    raise  # major debug client
                else:
                    self.app_log.info("Ending thread, because {}".format(e))
                    return

            finally:
                # self.peers.forget_mainnet(HOST)
                try:
                    conn.close()
                except:
                    pass
        if not self.peers.version_allowed(HOST, self.config.version_allow):
            self.app_log.warning("Outbound: Ending thread, because {} has too old a version: {}"
                            .format(HOST, self.peers.ip_to_mainnet[HOST]))



def main():
    mining_heavy3.mining_open()
    try:
        node = Node()
        node.start()
    finally:
        mining_heavy3.mining_close()


if __name__ == "__main__":
    main()
