import threading, socketserver, time, sqlite3, base64, hashlib

from Cryptodome.Hash import SHA
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5
from decimal import Decimal

from bismuth.core.ann import ann_get, ann_ver_get
from bismuth.core import regnet, mempool as mp, essentials, aliases, tokensv2 as tokens
from bismuth.core.utils import send, receive, quantize_two, quantize_eight


class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    def __init__(self, request, client_address, server):
        self.node = server.node
        self.app_log = server.node.app_log
        self.peers = server.node.peers
        self.plugin_manager = server.node.plugin_manager
        self.config = server.node.config
        super().__init__(request, client_address, server)

    def handle(self):
        node = self.node
        config = self.node.config

        if node.IS_STOPPING:
            return
        try:
            peer_ip = self.request.getpeername()[0]
        except:
            self.app_log.warning("Inbound: Transport endpoint was not connected");
            return
        # if threading.active_count() < thread_limit_conf or peer_ip == "127.0.0.1":
        # Always keep a slot for whitelisted (wallet could be there)
        if threading.active_count() < self.config.thread_limit_conf / 3 * 2 or self.peers.is_whitelisted(peer_ip):  # inbound
            capacity = True
        else:
            capacity = False
            try:
                self.request.close()
                self.app_log.info("Free capacity for {} unavailable, disconnected".format(peer_ip))
                # if you raise here, you kill the whole server
            except:
                pass
            finally:
                return

        banned = False
        dict_ip = {'ip': peer_ip}
        self.plugin_manager.execute_filter_hook('peer_ip', dict_ip)
        if self.peers.is_banned(peer_ip) or dict_ip['ip'] == 'banned':
            banned = True
            try:
                self.request.close()
                self.app_log.info("IP {} banned, disconnected".format(peer_ip))
            except:
                pass
            finally:
                return

        timeout_operation = 120  # timeout
        timer_operation = time.time()  # start counting

        while not banned and capacity and self.peers.version_allowed(peer_ip, self.config.version_allow) and not node.IS_STOPPING:
            try:
                hdd2, h2 = node.db_h2_define()
                conn, c = node.db_c_define()
                if self.config.full_ledger:
                    hdd, h = node.db_h_define()
                    h3 = h
                else:
                    hdd, h = None, None
                    h3 = h2

                index, index_cursor = node.index_define()

                # Failsafe
                if self.request == -1:
                    raise ValueError("Inbound: Closed socket from {}".format(peer_ip))
                    return
                if not time.time() <= timer_operation + timeout_operation:  # return on timeout
                    if node.peers.warning(self.request, peer_ip, "Operation timeout", 2):
                        self.app_log.info("{} banned".format(peer_ip))
                        break

                    raise ValueError("Inbound: Operation timeout from {}".format(peer_ip))

                data = receive(self.request)

                self.app_log.info("Inbound: Received: {} from {}".format(data, peer_ip))  # will add custom ports later

                if data.startswith('regtest_'):
                    if not node.is_regnet:
                        send(self.request, "notok")
                        return
                    else:
                        node.execute(c, ("SELECT block_hash FROM transactions WHERE block_height= (select max(block_height) from transactions)"))
                        block_hash = c.fetchone()[0]
                        # feed regnet with current thread db handle. refactor needed.
                        regnet.conn, regnet.c, regnet.hdd, regnet.h, regnet.hdd2, regnet.h2, regnet.h3 = conn, c, hdd, h, hdd2, h2, h3
                        regnet.command(self.request, data, block_hash)

                if data == 'version':
                    data = receive(self.request)
                    if data not in self.config.version_allow:
                        self.app_log.warning("Protocol version mismatch: {}, should be {}".format(data, self.config.version_allow))
                        send(self.request, "notok")
                        return
                    else:
                        self.app_log.warning("Inbound: Protocol version matched: {}".format(data))
                        send(self.request, "ok")
                        self.peers.store_mainnet(peer_ip, data)

                elif data == 'getversion':
                    send(self.request, config.version)

                elif data == 'mempool':

                    # receive theirs
                    segments = receive(self.request)
                    self.app_log.info(mp.MEMPOOL.merge(segments, peer_ip, c, False))

                    # receive theirs

                    # execute_param(m, ('SELECT timestamp,address,recipient,amount,signature,public_key,operation,openfield FROM transactions WHERE timeout < ? ORDER BY amount DESC;'), (int(time.time() - 5),))
                    if mp.MEMPOOL.sendable(peer_ip):
                        # Only send the diff
                        mempool_txs = mp.MEMPOOL.tx_to_send(peer_ip, segments)
                        # and note the time
                        mp.MEMPOOL.sent(peer_ip)
                    else:
                        # We already sent not long ago, send empy
                        mempool_txs = []

                    # send own
                    # self.app_log.info("Inbound: Extracted from the mempool: " + str(mempool_txs))  # improve: sync based on signatures only

                    # if len(mempool_txs) > 0: same as the other
                    send(self.request, mempool_txs)

                    # send own

                elif data == "hello":
                    if node.is_regnet:
                        self.app_log.info("Inbound: Got hello but I'm in regtest mode, closing.")
                        return

                    send(self.request, "peers")
                    send(self.request, self.peers.peer_list_old_format()) #INCOMPATIBLE WITH THE OLD WAY

                    while node.db_lock.locked():
                        time.sleep(quantize_two(config.pause_conf))
                    self.app_log.info("Inbound: Sending sync request")

                    send(self.request, "sync")

                elif data == "sendsync":
                    while node.db_lock.locked():
                        time.sleep(quantize_two(config.pause_conf))

                    while len(node.syncing) >= 3:
                        if node.IS_STOPPING:
                            return
                        time.sleep(int(config.pause_conf))

                    send(self.request, "sync")

                elif data == "blocksfnd":
                    self.app_log.info("Inbound: Client {} has the block(s)".format(
                        peer_ip))  # node should start sending txs in this step

                    # self.app_log.info("Inbound: Combined segments: " + segments)
                    # print peer_ip
                    if node.db_lock.locked():
                        self.app_log.info("Skipping sync from {}, syncing already in progress".format(peer_ip))

                    else:
                        node.execute(c, "SELECT timestamp FROM transactions WHERE reward != 0 ORDER BY block_height DESC LIMIT 1;")  # or it takes the first
                        last_block_ago = quantize_two(c.fetchone()[0])

                        if last_block_ago < time.time() - 600:
                            # block_req = most_common(consensus_blockheight_list)
                            block_req = self.peers.consensus_most_common
                            self.app_log.warning("Most common block rule triggered")

                        else:
                            # block_req = max(consensus_blockheight_list)
                            block_req = self.peers.consensus_max
                            self.app_log.warning("Longest chain rule triggered")

                        if int(received_block_height) >= block_req:

                            try:  # they claim to have the longest chain, things must go smooth or ban
                                self.app_log.warning("Confirming to sync from {}".format(peer_ip))
                                self.plugin_manager.execute_action_hook('sync', {'what': 'syncing_from', 'ip': peer_ip})
                                send(self.request, "blockscf")

                                segments = receive(self.request)

                            except:
                                if self.peers.warning(self.request, peer_ip, "Failed to deliver the longest chain"):
                                    self.app_log.info("{} banned".format(peer_ip))
                                    break
                            else:
                                node.digest_block(segments, self.request, peer_ip, conn, c, hdd, h, hdd2, h2, h3, index, index_cursor)

                                # receive theirs
                        else:
                            self.app_log.warning("Rejecting to sync from {}".format(peer_ip))
                            send(self.request, "blocksrj")
                            self.app_log.info("Inbound: Distant peer {} is at {}, should be at least {}".format(peer_ip, received_block_height, block_req))

                    send(self.request, "sync")

                elif data == "blockheight":
                    try:
                        received_block_height = receive(self.request)  # receive client's last block height
                        self.app_log.info("Inbound: Received block height {} from {} ".format(received_block_height, peer_ip))

                        # consensus pool 1 (connection from them)
                        consensus_blockheight = int(received_block_height)  # str int to remove leading zeros
                        # consensus_add(peer_ip, consensus_blockheight, self.request)
                        self.peers.consensus_add(peer_ip, consensus_blockheight, self.request, last_block)
                        # consensus pool 1 (connection from them)

                        node.execute(c, ('SELECT max(block_height) FROM transactions'))
                        db_block_height = c.fetchone()[0]

                        # append zeroes to get static length
                        send(self.request, db_block_height)
                        # send own block height

                        if int(received_block_height) > db_block_height:
                            self.app_log.warning("Inbound: Client has higher block")

                            node.execute(c, ('SELECT block_hash FROM transactions ORDER BY block_height DESC LIMIT 1'))
                            db_block_hash = c.fetchone()[0]  # get latest block_hash

                            self.app_log.info("Inbound: block_hash to send: " + str(db_block_hash))
                            send(self.request, db_block_hash)

                            # receive their latest hash
                            # confirm you know that hash or continue receiving

                        elif int(received_block_height) <= db_block_height:
                            if int(received_block_height) == db_block_height:
                                self.app_log.info("Inbound: We have the same height as {} ({}), hash will be verified".format(peer_ip, received_block_height))
                            else:
                                self.app_log.warning("Inbound: We have higher ({}) block height than {} ({}), hash will be verified".format(db_block_height, peer_ip, received_block_height))

                            data = receive(self.request)  # receive client's last block_hash
                            # send all our followup hashes

                            self.app_log.info("Inbound: Will seek the following block: {}".format(data))

                            try:
                                node.execute_param(h3, ("SELECT block_height FROM transactions WHERE block_hash = ?;"), (data,))
                                client_block = h3.fetchone()[0]

                                self.app_log.info("Inbound: Client is at block {}".format(client_block))  # now check if we have any newer

                                node.execute(h3, ('SELECT block_hash FROM transactions ORDER BY block_height DESC LIMIT 1'))
                                db_block_hash = h3.fetchone()[0]  # get latest block_hash
                                if db_block_hash == data or not config.egress:
                                    if not config.egress:
                                        self.app_log.warning("Outbound: Egress disabled for {}".format(peer_ip))
                                    else:
                                        self.app_log.info("Inbound: Client {} has the latest block".format(peer_ip))

                                    time.sleep(int(config.pause_conf))  # reduce CPU usage
                                    send(self.request, "nonewblk")

                                else:

                                    blocks_fetched = []
                                    del blocks_fetched[:]
                                    while len(str(blocks_fetched)) < 500000:  # limited size based on txs in blocks
                                        # execute_param(h3, ("SELECT block_height, timestamp,address,recipient,amount,signature,public_key,keep,openfield FROM transactions WHERE block_height > ? AND block_height <= ?;"),(str(int(client_block)),) + (str(int(client_block + 1)),))
                                        node.execute_param(h3, (
                                            "SELECT timestamp,address,recipient,amount,signature,public_key,cast(operation as TEXT),openfield FROM transactions WHERE block_height > ? AND block_height <= ?;"),
                                                      (str(int(client_block)), str(int(client_block + 1)),))
                                        result = h3.fetchall()
                                        if not result:
                                            break
                                        blocks_fetched.extend([result])
                                        client_block = int(client_block) + 1

                                    # blocks_send = [[l[1:] for l in group] for _, group in groupby(blocks_fetched, key=itemgetter(0))]  # remove block number

                                    # self.app_log.info("Inbound: Selected " + str(blocks_fetched) + " to send")

                                    send(self.request, "blocksfnd")

                                    confirmation = receive(self.request)

                                    if confirmation == "blockscf":
                                        self.app_log.info("Inbound: Client confirmed they want to sync from us")
                                        send(self.request, blocks_fetched)

                                    elif confirmation == "blocksrj":
                                        self.app_log.info("Inbound: Client rejected to sync from us because we're don't have the latest block")
                                        pass

                                        # send own

                            except Exception as e:
                                self.app_log.warning("Inbound: Block {} of {} not found".format(data[:8], peer_ip))
                                send(self.request, "blocknf")
                                send(self.request, data)
                    except Exception as e:
                        self.app_log.info("Inbound: Sync failed {}".format(e))

                elif data == "nonewblk":
                    send(self.request, "sync")

                elif data == "blocknf":
                    block_hash_delete = receive(self.request)
                    # print peer_ip
                    if consensus_blockheight == self.peers.consensus_max:
                        node.blocknf(block_hash_delete, peer_ip, conn, c, hdd, h, hdd2, h2)
                        if self.peers.warning(self.request, peer_ip, "Rollback", 2):
                            self.app_log.info("{} banned".format(peer_ip))
                            break
                    self.app_log.info("Outbound: Deletion complete, sending sync request")

                    while node.db_lock.locked():
                        if node.IS_STOPPING:
                            return
                        time.sleep(config.pause_conf)
                    send(self.request, "sync")

                elif data == "block":
                    # if (peer_ip in allowed or "any" in allowed):  # from miner
                    if self.peers.is_allowed(peer_ip, data):  # from miner
                        # TODO: rights management could be done one level higher instead of repeating the same check everywhere

                        self.app_log.info("Outbound: Received a block from miner {}".format(peer_ip))
                        # receive block
                        segments = receive(self.request)
                        # self.app_log.info("Inbound: Combined mined segments: " + segments)

                        # check if we have the latest block

                        node.execute(c, ('SELECT max(block_height) FROM transactions'))
                        db_block_height = int(c.fetchone()[0])

                        # check if we have the latest block

                        mined = {"timestamp": time.time(), "last": db_block_height, "ip": peer_ip, "miner": "",
                                 "result": False, "reason": ''}
                        try:
                            mined['miner'] = segments[0][-1][2]
                        except:
                            pass
                        if node.is_mainnet:
                            if len(self.peers.connection_pool) < 5 and not self.peers.is_whitelisted(peer_ip):
                                reason = "Outbound: Mined block ignored, insufficient connections to the network"
                                mined['reason'] = reason
                                self.plugin_manager.execute_action_hook('mined', mined)
                                self.app_log.info(reason)
                            elif node.db_lock.locked():
                                reason = "Outbound: Block from miner skipped because we are digesting already"
                                mined['reason'] = reason
                                self.plugin_manager.execute_action_hook('mined', mined)
                                self.app_log.warning(reason)
                            elif db_block_height >= self.peers.consensus_max - 3:
                                mined['result'] = True
                                self.plugin_manager.execute_action_hook('mined', mined)
                                self.app_log.info("Outbound: Processing block from miner")
                                node.digest_block(segments, self.request, peer_ip, conn, c, hdd, h, hdd2, h2, h3, index,
                                             index_cursor)
                            else:
                                reason = "Outbound: Mined block was orphaned because node was not synced, we are at block {}, should be at least {}".format(
                                    db_block_height, self.peers.consensus_max - 3)
                                mined['reason'] = reason
                                self.plugin_manager.execute_action_hook('mined', mined)
                                self.app_log.warning(reason)
                        else:
                            node.digest_block(segments, self.request, peer_ip, conn, c, hdd, h, hdd2, h2, h3, index,
                                         index_cursor)
                    else:
                        receive(self.request)  # receive block, but do nothing about it
                        self.app_log.info("{} not whitelisted for block command".format(peer_ip))

                elif data == "blocklast":
                    # if (peer_ip in allowed or "any" in allowed):  # only sends the miner part of the block!
                    if self.peers.is_allowed(peer_ip, data):
                        node.execute(c, ("SELECT * FROM transactions WHERE reward != 0 ORDER BY block_height DESC LIMIT 1;"))
                        block_last = c.fetchall()[0]

                        send(self.request, block_last)
                    else:
                        self.app_log.info("{} not whitelisted for blocklast command".format(peer_ip))

                elif data == "blocklastjson":
                    # if (peer_ip in allowed or "any" in allowed):  # only sends the miner part of the block!
                    if self.peers.is_allowed(peer_ip, data):
                        node.execute(c, ("SELECT * FROM transactions WHERE reward != 0 ORDER BY block_height DESC LIMIT 1;"))
                        block_last = c.fetchall()[0]

                        response = {"block_height": block_last[0],
                                    "timestamp": block_last[1],
                                    "address": block_last[2],
                                    "recipient": block_last[3],
                                    "amount": block_last[4],
                                    "signature": block_last[5],
                                    "public_key": block_last[6],
                                    "block_hash": block_last[7],
                                    "fee": block_last[8],
                                    "reward": block_last[9],
                                    "operation": block_last[10],
                                    "nonce": block_last[11]}

                        send(self.request, response)
                    else:
                        self.app_log.info("{} not whitelisted for blocklastjson command".format(peer_ip))

                elif data == "blockget":
                    # if (peer_ip in allowed or "any" in allowed):
                    if self.peers.is_allowed(peer_ip, data):
                        block_desired = receive(self.request)

                        node.execute_param(h3, ("SELECT * FROM transactions WHERE block_height = ?;"), (block_desired,))
                        block_desired_result = h3.fetchall()

                        send(self.request, block_desired_result)
                    else:
                        self.app_log.info("{} not whitelisted for blockget command".format(peer_ip))

                elif data == "blockgetjson":
                    # if (peer_ip in allowed or "any" in allowed):
                    if self.peers.is_allowed(peer_ip, data):
                        block_desired = receive(self.request)

                        node.execute_param(h3, ("SELECT * FROM transactions WHERE block_height = ?;"), (block_desired,))
                        block_desired_result = h3.fetchall()

                        response_list = []
                        for transaction in block_desired_result:
                            response = {"block_height": transaction[0],
                                        "timestamp": transaction[1],
                                        "address": transaction[2],
                                        "recipient": transaction[3],
                                        "amount": transaction[4],
                                        "signature": transaction[5],
                                        "public_key": transaction[6],
                                        "block_hash": transaction[7],
                                        "fee": transaction[8],
                                        "reward": transaction[9],
                                        "operation": transaction[10],
                                        "openfield": transaction[11]}

                            response_list.append(response)

                        send(self.request, response_list)
                    else:
                        self.app_log.info("{} not whitelisted for blockget command".format(peer_ip))

                elif data == "mpinsert":
                    # if (peer_ip in allowed or "any" in allowed):
                    if self.peers.is_allowed(peer_ip, data):
                        mempool_insert = receive(self.request)
                        self.app_log.warning("mpinsert command")

                        mpinsert_result = mp.MEMPOOL.merge(mempool_insert, peer_ip, c, True, True)
                        self.app_log.warning("mpinsert result: {}".format(mpinsert_result))
                        send(self.request, mpinsert_result)
                    else:
                        self.app_log.info("{} not whitelisted for mpinsert command".format(peer_ip))

                elif data == "balanceget":
                    # if (peer_ip in allowed or "any" in allowed):
                    if self.peers.is_allowed(peer_ip, data):
                        balance_address = receive(self.request)  # for which address

                        balanceget_result = node.balanceget(balance_address, c)

                        send(self.request, balanceget_result)  # return balance of the address to the client, including mempool
                        # send(self.request, balance_pre)  # return balance of the address to the client, no mempool
                    else:
                        self.app_log.info("{} not whitelisted for balanceget command".format(peer_ip))

                elif data == "balancegetjson":
                    # if (peer_ip in allowed or "any" in allowed):
                    if self.peers.is_allowed(peer_ip, data):
                        balance_address = receive(self.request)  # for which address

                        balanceget_result = node.balanceget(balance_address, c)
                        response = {"balance": balanceget_result[0],
                                    "credit": balanceget_result[1],
                                    "debit": balanceget_result[0],
                                    "fees": balanceget_result[0],
                                    "rewards": balanceget_result[0],
                                    "balance_no_mempool": balanceget_result[0]}

                        send(self.request, response)  # return balance of the address to the client, including mempool
                        # send(self.request, balance_pre)  # return balance of the address to the client, no mempool
                    else:
                        self.app_log.info("{} not whitelisted for balancegetjson command".format(peer_ip))

                elif data == "mpgetjson" and self.peers.is_allowed(peer_ip, data):
                    mempool_txs = mp.MEMPOOL.fetchall(mp.SQL_SELECT_TX_TO_SEND)

                    response_list = []
                    for transaction in mempool_txs:
                        response = {"timestamp": transaction[0],
                                    "address": transaction[1],
                                    "recipient": transaction[2],
                                    "amount": transaction[3],
                                    "signature": transaction[4],
                                    "public_key": transaction[5],
                                    "operation": transaction[6],
                                    "openfield": transaction[7]}

                        response_list.append(response)

                    # self.app_log.info("Outbound: Extracted from the mempool: " + str(mempool_txs))  # improve: sync based on signatures only

                    # if len(mempool_txs) > 0: #wont sync mempool until we send something, which is bad
                    # send own
                    send(self.request, response_list)

                elif data == "mpget" and self.peers.is_allowed(peer_ip, data):
                    mempool_txs = mp.MEMPOOL.fetchall(mp.SQL_SELECT_TX_TO_SEND)

                    # self.app_log.info("Outbound: Extracted from the mempool: " + str(mempool_txs))  # improve: sync based on signatures only

                    # if len(mempool_txs) > 0: #wont sync mempool until we send something, which is bad
                    # send own
                    send(self.request, mempool_txs)

                elif data == "mpclear" and peer_ip == "127.0.0.1":  # reserved for localhost
                    mp.MEMPOOL.clear()
                    node.commit(mempool)

                elif data == "keygen":
                    # if (peer_ip in allowed or "any" in allowed):
                    if self.peers.is_allowed(peer_ip, data):
                        (gen_private_key_readable, gen_public_key_readable, gen_address) = keys.generate()
                        send(self.request, (gen_private_key_readable, gen_public_key_readable, gen_address))
                        (gen_private_key_readable, gen_public_key_readable, gen_address) = (None, None, None)
                    else:
                        self.app_log.info("{} not whitelisted for keygen command".format(peer_ip))

                elif data == "keygenjson":
                    # if (peer_ip in allowed or "any" in allowed):
                    if self.peers.is_allowed(peer_ip, data):
                        (gen_private_key_readable, gen_public_key_readable, gen_address) = keys.generate()
                        response = {"private_key": gen_private_key_readable,
                                    "public_key": gen_public_key_readable,
                                    "address": gen_address}

                        send(self.request, response)
                        (gen_private_key_readable, gen_public_key_readable, gen_address) = (None, None, None)
                    else:
                        self.app_log.info("{} not whitelisted for keygen command".format(peer_ip))

                elif data == "addlist":
                    # if (peer_ip in allowed or "any" in allowed):
                    if self.peers.is_allowed(peer_ip, data):
                        address_tx_list = receive(self.request)
                        node.execute_param(h3, ("SELECT * FROM transactions WHERE (address = ? OR recipient = ?) ORDER BY block_height DESC"), (address_tx_list, address_tx_list,))
                        result = h3.fetchall()
                        send(self.request, result)
                    else:
                        self.app_log.info("{} not whitelisted for addlist command".format(peer_ip))

                elif data == "listlimjson":
                    # if (peer_ip in allowed or "any" in allowed):
                    if self.peers.is_allowed(peer_ip, data):
                        list_limit = receive(self.request)
                        # print(address_tx_list_limit)
                        node.execute_param(h3, ("SELECT * FROM transactions ORDER BY block_height DESC LIMIT ?"), (list_limit,))
                        result = h3.fetchall()

                        response_list = []
                        for transaction in result:
                            response = {"block_height": transaction[0],
                                        "timestamp": transaction[1],
                                        "address": transaction[2],
                                        "recipient": transaction[3],
                                        "amount": transaction[4],
                                        "signature": transaction[5],
                                        "public_key": transaction[6],
                                        "block_hash": transaction[7],
                                        "fee": transaction[8],
                                        "reward": transaction[9],
                                        "operation": transaction[10],
                                        "openfield": transaction[11]}

                            response_list.append(response)

                        send(self.request, response_list)
                    else:
                        self.app_log.info("{} not whitelisted for listlimjson command".format(peer_ip))

                elif data == "listlim":
                    # if (peer_ip in allowed or "any" in allowed):
                    if self.peers.is_allowed(peer_ip, data):
                        list_limit = receive(self.request)
                        # print(address_tx_list_limit)
                        node.execute_param(h3, ("SELECT * FROM transactions ORDER BY block_height DESC LIMIT ?"), (list_limit,))
                        result = h3.fetchall()
                        send(self.request, result)
                    else:
                        self.app_log.info("{} not whitelisted for listlim command".format(peer_ip))

                elif data == "addlistlim":
                    # if (peer_ip in allowed or "any" in allowed):
                    if self.peers.is_allowed(peer_ip, data):
                        address_tx_list = receive(self.request)
                        address_tx_list_limit = receive(self.request)

                        # print(address_tx_list_limit)
                        node.execute_param(h3, ("SELECT * FROM transactions WHERE (address = ? OR recipient = ?) ORDER BY block_height DESC LIMIT ?"), (address_tx_list, address_tx_list, address_tx_list_limit,))
                        result = h3.fetchall()
                        send(self.request, result)
                    else:
                        self.app_log.info("{} not whitelisted for addlistlim command".format(peer_ip))

                elif data == "addlistlimjson":
                    # if (peer_ip in allowed or "any" in allowed):
                    if self.peers.is_allowed(peer_ip, data):
                        address_tx_list = receive(self.request)
                        address_tx_list_limit = receive(self.request)

                        # print(address_tx_list_limit)
                        node.execute_param(h3, ("SELECT * FROM transactions WHERE (address = ? OR recipient = ?) ORDER BY block_height DESC LIMIT ?"), (address_tx_list, address_tx_list, address_tx_list_limit,))
                        result = h3.fetchall()

                        response_list = []
                        for transaction in result:
                            response = {"block_height": transaction[0],
                                        "timestamp": transaction[1],
                                        "address": transaction[2],
                                        "recipient": transaction[3],
                                        "amount": transaction[4],
                                        "signature": transaction[5],
                                        "public_key": transaction[6],
                                        "block_hash": transaction[7],
                                        "fee": transaction[8],
                                        "reward": transaction[9],
                                        "operation": transaction[10],
                                        "openfield": transaction[11]}

                            response_list.append(response)

                        send(self.request, response_list)
                    else:
                        self.app_log.info("{} not whitelisted for addlistlimjson command".format(peer_ip))

                elif data == "addlistlimmir":
                    # if (peer_ip in allowed or "any" in allowed):
                    if self.peers.is_allowed(peer_ip, data):
                        address_tx_list = receive(self.request)
                        address_tx_list_limit = receive(self.request)

                        # print(address_tx_list_limit)
                        node.execute_param(h3, ("SELECT * FROM transactions WHERE (address = ? OR recipient = ?) AND block_height < 1 ORDER BY block_height ASC LIMIT ?"), (address_tx_list, address_tx_list, address_tx_list_limit,))
                        result = h3.fetchall()
                        send(self.request, result)
                    else:
                        self.app_log.info("{} not whitelisted for addlistlimmir command".format(peer_ip))

                elif data == "addlistlimmirjson":
                    # if (peer_ip in allowed or "any" in allowed):
                    if self.peers.is_allowed(peer_ip, data):
                        address_tx_list = receive(self.request)
                        address_tx_list_limit = receive(self.request)

                        # print(address_tx_list_limit)
                        node.execute_param(h3, ("SELECT * FROM transactions WHERE (address = ? OR recipient = ?) AND block_height < 1 ORDER BY block_height ASC LIMIT ?"), (address_tx_list, address_tx_list, address_tx_list_limit,))
                        result = h3.fetchall()

                        response_list = []
                        for transaction in result:
                            response = {"block_height": transaction[0],
                                        "timestamp": transaction[1],
                                        "address": transaction[2],
                                        "recipient": transaction[3],
                                        "amount": transaction[4],
                                        "signature": transaction[5],
                                        "public_key": transaction[6],
                                        "block_hash": transaction[7],
                                        "fee": transaction[8],
                                        "reward": transaction[9],
                                        "operation": transaction[10],
                                        "openfield": transaction[11]}

                            response_list.append(response)

                        send(self.request, response_list)

                        send(self.request, result)
                    else:
                        self.app_log.info("{} not whitelisted for addlistlimmir command".format(peer_ip))

                elif data == "aliasget":  # all for a single address, no protection against overlapping
                    # if (peer_ip in allowed or "any" in allowed):
                    if self.peers.is_allowed(peer_ip, data):
                        aliases.aliases_update(node.index_db, config.ledger_path_conf, "normal", self.app_log)

                        alias_address = receive(self.request)

                        node.execute_param(index_cursor, ("SELECT alias FROM aliases WHERE address = ? "), (alias_address,))

                        result = index_cursor.fetchall()

                        if not result:
                            result = [[alias_address]]

                        send(self.request, result)
                    else:
                        self.app_log.info("{} not whitelisted for aliasget command".format(peer_ip))

                elif data == "aliasesget":  # only gets the first one, for multiple addresses
                    # if (peer_ip in allowed or "any" in allowed):
                    if self.peers.is_allowed(peer_ip, data):
                        aliases.aliases_update(node.index_db, config.ledger_path_conf, "normal", self.app_log)

                        aliases_request = receive(self.request)

                        results = []
                        for alias_address in aliases_request:
                            node.execute_param(index_cursor, (
                                "SELECT alias FROM aliases WHERE address = ? ORDER BY block_height ASC LIMIT 1"),
                                          (alias_address,))
                            try:
                                result = index_cursor.fetchall()[0][0]
                            except:
                                result = alias_address
                            results.append(result)

                        send(self.request, results)
                    else:
                        self.app_log.info("{} not whitelisted for aliasesget command".format(peer_ip))

                # Not mandatory, but may help to reindex with minimal sql queries
                elif data == "tokensupdate":
                    if self.peers.is_allowed(peer_ip, data):
                        tokens.tokens_update(node.index_db, config.ledger_path_conf, "normal", self.app_log, self.plugin_manager)
                #
                elif data == "tokensget":
                    if self.peers.is_allowed(peer_ip, data):
                        tokens.tokens_update(node.index_db, config.ledger_path_conf, "normal", self.app_log, self.plugin_manager)
                        tokens_address = receive(self.request)

                        index_cursor.execute("SELECT DISTINCT token FROM tokens WHERE address OR recipient = ?", (tokens_address,))
                        tokens_user = index_cursor.fetchall()

                        tokens_list = []
                        for token in tokens_user:
                            token = token[0]
                            index_cursor.execute("SELECT sum(amount) FROM tokens WHERE recipient = ? AND token = ?;",
                                                 (tokens_address,) + (token,))
                            credit = index_cursor.fetchone()[0]
                            index_cursor.execute("SELECT sum(amount) FROM tokens WHERE address = ? AND token = ?;",
                                                 (tokens_address,) + (token,))
                            debit = index_cursor.fetchone()[0]

                            debit = 0 if debit is None else debit
                            credit = 0 if credit is None else credit

                            balance = str(Decimal(credit) - Decimal(debit))

                            tokens_list.append((token, balance))

                        send(self.request, tokens_list)
                    else:
                        self.app_log.info("{} not whitelisted for tokensget command".format(peer_ip))

                elif data == "addfromalias":
                    if self.peers.is_allowed(peer_ip, data):

                        aliases.aliases_update(node.index_db, config.ledger_path_conf, "normal", self.app_log)

                        alias_address = receive(self.request)
                        index_cursor.execute(
                            "SELECT address FROM aliases WHERE alias = ? ORDER BY block_height ASC LIMIT 1;",
                            (alias_address,))  # asc for first entry
                        try:
                            address_fetch = index_cursor.fetchone()[0]
                        except:
                            address_fetch = "No alias"
                        self.app_log.warning("Fetched the following alias address: {}".format(address_fetch))

                        send(self.request, address_fetch)

                        ali.close()

                    else:
                        self.app_log.info("{} not whitelisted for addfromalias command".format(peer_ip))

                elif data == "pubkeyget":
                    # if (peer_ip in allowed or "any" in allowed):
                    if self.peers.is_allowed(peer_ip, data):
                        pub_key_address = receive(self.request)

                        c.execute("SELECT public_key FROM transactions WHERE address = ? and reward = 0 LIMIT 1",
                                  (pub_key_address,))
                        target_public_key_hashed = c.fetchone()[0]
                        send(self.request, target_public_key_hashed)

                    else:
                        self.app_log.info("{} not whitelisted for pubkeyget command".format(peer_ip))

                elif data == "aliascheck":
                    # if (peer_ip in allowed or "any" in allowed):
                    if self.peers.is_allowed(peer_ip, data):
                        reg_string = receive(self.request)

                        registered_pending = mp.MEMPOOL.fetchone(
                            "SELECT timestamp FROM transactions WHERE openfield = ?;",
                            ("alias=" + reg_string,))

                        h3.execute("SELECT timestamp FROM transactions WHERE openfield = ?;", ("alias=" + reg_string,))
                        registered_already = h3.fetchone()

                        if registered_already is None and registered_pending is None:
                            send(self.request, "Alias free")
                        else:
                            send(self.request, "Alias registered")
                    else:
                        self.app_log.info("{} not whitelisted for aliascheck command".format(peer_ip))

                elif data == "txsend":
                    # if (peer_ip in allowed or "any" in allowed):
                    if self.peers.is_allowed(peer_ip, data):
                        tx_remote = receive(self.request)

                        # receive data necessary for remote tx construction
                        remote_tx_timestamp = tx_remote[0]
                        remote_tx_privkey = tx_remote[1]
                        remote_tx_recipient = tx_remote[2]
                        remote_tx_amount = tx_remote[3]
                        remote_tx_operation = tx_remote[4]
                        remote_tx_openfield = tx_remote[5]
                        # receive data necessary for remote tx construction

                        # derive remaining data
                        tx_remote_key = RSA.importKey(remote_tx_privkey)
                        remote_tx_pubkey = tx_remote_key.publickey().exportKey().decode("utf-8")

                        remote_tx_pubkey_hashed = base64.b64encode(remote_tx_pubkey.encode('utf-8')).decode("utf-8")

                        remote_tx_address = hashlib.sha224(remote_tx_pubkey.encode("utf-8")).hexdigest()
                        # derive remaining data

                        # construct tx
                        remote_tx = (str(remote_tx_timestamp), str(remote_tx_address), str(remote_tx_recipient),
                                     '%.8f' % quantize_eight(remote_tx_amount), str(remote_tx_operation),
                                     str(remote_tx_openfield))  # this is signed

                        remote_hash = SHA.new(str(remote_tx).encode("utf-8"))
                        remote_signer = PKCS1_v1_5.new(tx_remote_key)
                        remote_signature = remote_signer.sign(remote_hash)
                        remote_signature_enc = base64.b64encode(remote_signature).decode("utf-8")
                        # construct tx

                        # insert to mempool, where everything will be verified
                        mempool_data = ((str(remote_tx_timestamp), str(remote_tx_address), str(remote_tx_recipient),
                                         '%.8f' % quantize_eight(remote_tx_amount), str(remote_signature_enc),
                                         str(remote_tx_pubkey_hashed), str(remote_tx_operation),
                                         str(remote_tx_openfield)))

                        self.app_log.info(mp.MEMPOOL.merge(mempool_data, peer_ip, c, True, True))

                        send(self.request, str(remote_signature_enc))
                        # wipe variables
                        (tx_remote, remote_tx_privkey, tx_remote_key) = (None, None, None)
                    else:
                        self.app_log.info("{} not whitelisted for txsend command".format(peer_ip))

                # less important methods
                elif data == "addvalidate":
                    # if (peer_ip in allowed or "any" in allowed):
                    if self.peers.is_allowed(peer_ip, data):

                        address_to_validate = receive(self.request)
                        if essentials.address_validate(address_to_validate):
                            result = "valid"
                        else:
                            result = "invalid"

                        send(self.request, result)
                    else:
                        self.app_log.info("{} not whitelisted for addvalidate command".format(peer_ip))

                elif data == "annget":
                    # if (peer_ip in allowed or "any" in allowed):
                    if self.peers.is_allowed(peer_ip, data):

                        # with open(peerlist, "r") as peer_list:
                        #    peers_file = peer_list.read()
                        send(self.request, ann_get(h3, config.genesis_conf))
                    else:
                        self.app_log.info("{} not whitelisted for annget command".format(peer_ip))

                elif data == "annverget":
                    # if (peer_ip in allowed or "any" in allowed):
                    if self.peers.is_allowed(peer_ip, data):

                        # with open(peerlist, "r") as peer_list:
                        #    peers_file = peer_list.read()
                        send(self.request, ann_ver_get(h3, config.genesis_conf))

                    else:
                        self.app_log.info("{} not whitelisted for annget command".format(peer_ip))

                elif data == "peersget":
                    # if (peer_ip in allowed or "any" in allowed):
                    if self.peers.is_allowed(peer_ip, data):

                        # with open(peerlist, "r") as peer_list:
                        #    peers_file = peer_list.read()
                        send(self.request, self.peers.peer_list_disk_format())

                    else:
                        self.app_log.info("{} not whitelisted for peersget command".format(peer_ip))

                elif data == "statusget":
                    # if (peer_ip in allowed or "any" in allowed):
                    if self.peers.is_allowed(peer_ip, data):

                        nodes_count = self.peers.consensus_size
                        nodes_list = self.peers.peer_ip_list
                        threads_count = threading.active_count()
                        uptime = int(time.time() - node.startup_time)
                        diff = node.difficulty(c)
                        server_timestamp = '%.2f' % time.time()

                        if config.reveal_address:
                            revealed_address = node.address
                        else:
                            revealed_address = "private"

                        send(self.request, (
                            revealed_address, nodes_count, nodes_list, threads_count, uptime, self.peers.consensus,
                            self.peers.consensus_percentage, node.VERSION, diff, server_timestamp))

                    else:
                        self.app_log.info("{} not whitelisted for statusget command".format(peer_ip))

                elif data == "statusjson":
                    if self.peers.is_allowed(peer_ip, data):
                        uptime = int(time.time() - node.startup_time)
                        tempdiff = node.difficulty(c)

                        if config.reveal_address:
                            revealed_address = node.address
                        else:
                            revealed_address = "private"

                        status = {"protocolversion": config.version_conf,
                                  "address": revealed_address,
                                  "walletversion": node.VERSION,
                                  "testnet": self.peers.is_testnet,  # config data
                                  "blocks": node.last_block,
                                  "timeoffset": 0,
                                  "connections": self.peers.consensus_size,
                                  "connections_list": self.peers.peer_ip_list,
                                  "difficulty": tempdiff[0],  # live status, bitcoind format
                                  "threads": threading.active_count(),
                                  "uptime": uptime,
                                  "consensus": self.peers.consensus,
                                  "consensus_percent": self.peers.consensus_percentage,
                                  "server_timestamp": '%.2f' % time.time()}  # extra data
                        if node.is_regnet:
                            status['regnet'] = True
                        send(self.request, status)
                    else:
                        self.app_log.info("{} not whitelisted for statusjson command".format(peer_ip))
                elif data[:4] == 'api_':
                    if self.peers.is_allowed(peer_ip, data):
                        try:
                            node.apihandler.dispatch(data, self.request, h3, node.peers)
                        except Exception as e:
                            print(e)

                elif data == "diffget":
                    # if (peer_ip in allowed or "any" in allowed):
                    if self.peers.is_allowed(peer_ip, data):
                        diff = node.difficulty(c)
                        send(self.request, diff)
                    else:
                        self.app_log.info("{} not whitelisted for diffget command".format(peer_ip))

                elif data == "diffgetjson":
                    # if (peer_ip in allowed or "any" in allowed):
                    if self.peers.is_allowed(peer_ip, data):
                        diff = node.difficulty(c)
                        response = {"difficulty": diff[0],
                                    "diff_dropped": diff[0],
                                    "time_to_generate": diff[0],
                                    "diff_block_previous": diff[0],
                                    "block_time": diff[0],
                                    "hashrate": diff[0],
                                    "diff_adjustment": diff[0],
                                    "block_height": diff[0]}

                        send(self.request, response)
                    else:
                        self.app_log.info("{} not whitelisted for diffgetjson command".format(peer_ip))

                elif data == "difflast":
                    # if (peer_ip in allowed or "any" in allowed):
                    if self.peers.is_allowed(peer_ip, data):

                        node.execute(h3, ("SELECT block_height, difficulty FROM misc ORDER BY block_height DESC LIMIT 1"))
                        difflast = h3.fetchone()
                        send(self.request, difflast)
                    else:
                        self.app_log.info("{} not whitelisted for difflastget command".format(peer_ip))

                elif data == "difflastjson":
                    # if (peer_ip in allowed or "any" in allowed):
                    if self.peers.is_allowed(peer_ip, data):

                        node.execute(h3, ("SELECT block_height, difficulty FROM misc ORDER BY block_height DESC LIMIT 1"))
                        difflast = h3.fetchone()
                        response = {"block": difflast[0],
                                    "difficulty": difflast[1]
                                    }
                        send(self.request, response)
                    else:
                        self.app_log.info("{} not whitelisted for difflastjson command".format(peer_ip))

                elif data == "stop":
                    # if (peer_ip in allowed or "any" in allowed):
                    if self.peers.is_allowed(peer_ip, data):
                        self.app_log.warning("Received stop from {}".format(peer_ip))
                        node.IS_STOPPING = True
                else:
                    if data == '*':
                        raise ValueError("Broken pipe")
                    raise ValueError("Unexpected error, received: " + str(data)[:32] + ' ...')

                if not time.time() <= timer_operation + timeout_operation:
                    timer_operation = time.time()  # reset timer
                # time.sleep(float(pause_conf))  # prevent cpu overload
                self.app_log.info("Server loop finished for {}".format(peer_ip))

            except Exception as e:
                self.app_log.info("Inbound: Lost connection to {}".format(peer_ip))
                self.app_log.info("Inbound: {}".format(e))

                # remove from consensus (connection from them)
                self.peers.consensus_remove(peer_ip)
                # remove from consensus (connection from them)
                if self.request:
                    self.request.close()

                if config.debug_conf:
                    raise  # major debug client
                else:
                    return

            finally:
                # cleanup
                # self.peers.forget_mainnet(peer_ip)
                try:
                    if conn:
                        conn.close()
                except Exception as e:
                    self.app_log.info("Error closing conn {}".format(e))
        if not self.peers.version_allowed(peer_ip, self.config.version_allow):
            self.app_log.warning("Inbound: Closing connection to old {} node: {}"
                            .format(peer_ip, self.peers.ip_to_mainnet['peer_ip']))
