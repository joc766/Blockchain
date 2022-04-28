import socket
import socketserver
import threading
import secrets
import time
import hashlib
import json
import pprint
import sys
from queue import Queue, Empty # added Empty exception
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

# global constants
NNODES = 6
DIFFICULTY = 10 # larger number = takes (exponentially) longer to mine
STOPPING   = 8  # how long the chain should get before we stop


class Blockchain():

    def __init__( self, info, peers ):

        # node info
        self.ip   = info[ 'ip' ]         # ip address of node, always 127.0.0.1
        self.port = info[ 'port' ]       # port of node
        self.sign_key    = info[ 'sk' ]  # pyca object for signing key of node
        self.verify_key  = info[ 'epk' ] # hex encoded public key for use in transactions
        self._verify_key = info[ 'pk' ]  # pyca object for verification key of node

        # dict of other nodes key'd by port
        self.peers = peers

        # chain data structures and information
        self.blocks = {}              # all known blocks, from current and side chains
        self.head   = None            # head of the current chain
        self.length = 0               # length of the current chain
        self.difficulty = DIFFICULTY  # mining difficulty

        # inbound blocks received from the network
        self.pending = Queue()

        # list of currently owned coins
        self.wallet = []

        # if role, create and distribute genesis block
        self.genesis()


    # create genesis block
    def genesis( self ):

        if not self.port == 8001:
            return

        block, digest = self.find_block( float('inf'), 0, 0, [] )

        if block is None or digest is None:
            print( "node {} failed to create genesis block".format( self.port ) )
            exit( 1 )

        self.serialize( block, digest )
        time.sleep( 5 ) # pedagogical hack, ignore if reading code

    # serialize and distribute block
    def serialize( self, block, digest ):
        print( 'node {} broadcasting'.format( self.port) )

        self.blocks[ digest ] = block
        self.pending.put( digest )

        payload = { 'block' : block, 'digest' : digest }
        encoded = json.dumps( payload ).encode( 'utf-8' )

        for peer in peers.keys():
            if peer == self.port:
                continue

            with socket.socket( socket.AF_INET, socket.SOCK_STREAM ) as sock:
                sock.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1 )
                try:
                    sock.connect( ( peers[ peer ][ 'ip' ], peers[ peer ][ 'port' ] ) )
                    sock.sendall( encoded )
                except Exception as e:
                    print(e)

        return

    # deserialize block
    def deserialize( self, data ):
        # wanna add a self.pending.join() call here
        payload = json.loads( data )

        self.blocks[ payload[ 'digest' ] ] = payload[ 'block' ]
        self.pending.put( payload[ 'digest' ] )

        return ( payload[ 'block' ], payload[ 'digest' ] )
    
    # makes things cleaner. Outputs a list in order of the chain
    def get_chain( self, start=None ):
        if start is None:
            start = self.head
        chain = []
        curr = self.blocks.get(start)
        while curr is not None:
            chain.insert(0, curr)
            curr = self.blocks.get(curr['header']['parent'])
        return chain

    def verify_last_txn( self ):
        #####
        ## verify_last_txn implements a transaction chain verification. To do this,
        ## it iterates over blocks in a chain to find non-mining transactions to verify
        ## and grab the metadata from.
        ##
        ## For Part 3, verify_last_txn iterates over `self.blocks.keys()` to verify the 
        ## last transaction chain. Begin your search at the current chain's 
        ## head looking for non-mining transactions. Make sure to run `verify_txn`
        ## and raise any exceptions that might be caused by `lookup_key`, a function you
        ## should have used in `verify_txn`.
        ## Once a non-mining transaction is found, continue traversing
        ## through its links by utilizing metadata such as prev_txn_index
        ## in order to fully verify the transaction.
        ## 
        ## Does not return, just prints the last non-mining transaction's sender,
        ## recipient, and block index, if it exists, in the following format on a new line:
        ## '\nverified last non-mining trasaction: {sender} sent {receipient} a coin in block indexed {index}'.
        ## If it does not exist, print '\nno mining transactions occurred...'
        chain = self.get_chain()
        chain.reverse() # reverse so iterate from head to genesis
        last_txn = None
        for block in chain:
            for txn in block['transactions']:
                if not txn['metadata']['mined'] and self.verify_txn(txn): # lookup_key exception handled in verify_txn() 
                    last_txn = txn
                    last_txn_block_index = block['header']['index']
                    break
            if last_txn is not None:
                break
        chain.reverse() # reverse again so the indices are valid
        
        # Now we have a non-mining transaction
        curr_txn = last_txn
        if last_txn is None:
            print('\nno mining transactions occurred...')
            return
        try:
            while curr_txn is not None:
                prev_txn = None
                prev_block = chain[curr_txn['metadata']['prev_txn_index']]
                for txn in prev_block['transactions']:
                    if txn['data']['digest'] == self.hash_txn(curr_txn['data']['recipient'], curr_txn['data']['digest'], curr_txn['data']['signature']):
                        if self.verify_txn(txn):
                            prev_txn = txn
                            break
                        else:
                            raise ValueError("Invalid transaction found during verification")
                else:
                    curr_txn = prev_txn
        except ValueError as e:
            print(e)
            print('\nno mining transactions occurred...')
        else:
            sender = self.lookup_key(last_txn['metadata']['sender'])
            recipient = last_txn['data']['recipient']
            index = last_txn_block_index
            print(f'\nverified last non-mining trasaction: {sender} sent {recipient} a coin in block indexed {index}')
        
            
                
                
        
        



    def get_timestamp( self ):
        return time.time()

    def get_nonce( self ):
        return secrets.token_hex( 32 )

    def hash_block( self, block ):
        m = hashlib.sha256()
        m.update( json.dumps( block ).encode( 'utf-8' ) )
        return m.hexdigest().zfill( 32 )

    def hash_txn( self, recipient, digest, signature ):
        m = hashlib.sha256()
        m.update( 'r:{}h:{}s:{}'.format( recipient, digest, signature ).encode( 'utf-8' ) )
        return m.hexdigest().zfill( 32 )

    def hash_txn_with_recipient( self, txn, recipient ):
        m = hashlib.sha256()
        m.update( 't:{}r:{}'.format( txn, recipient ).encode( 'utf-8' ) )
        return m.hexdigest().zfill( 32 )

    # get number of leading zeros in a hash
    def leading( self, digest ):
        return 256 - len( bin( int( digest, 16 ) )[ 2: ].zfill( 256 ).lstrip( '0' ) )

    # lookup a public key by peer name (port number)
    def lookup_key( self, peer ):
        return self.peers[ peer ][ 'epk' ]

    # sign a digest
    def sign( self, digest ):
        signature = self.sign_key.sign( int( digest, 16 ).to_bytes( 32, sys.byteorder ) )
        return hex( int.from_bytes( signature, byteorder = sys.byteorder ) )[ 2: ].zfill( 64 )

    # verify a transaction
    def verify( self, verify_key, digest, signature ):
        # as a quick optimization for this toy implementation, we're gonna look the key up instead of loading it from hex
        peer = list( filter( lambda x: peers[ x ][ 'epk' ] == verify_key, peers.keys() ) ).pop()
        _verify_key = peers[ peer ][ 'pk' ]
        return _verify_key.verify( int( signature, 16 ).to_bytes( 64, sys.byteorder ), int( digest, 16 ).to_bytes( 32, sys.byteorder ) )

    def find_block( self, tries, index, parent, txns ):
        #####
        ## find_block implements mining (aka block creation). You must
        ## use the following block object (filled in, of course), as well
        ## as use the following txn object for Part 3.
        ##
        ## For Part 1, your code must use inputs `index`, `parent`, `txns`,
        ## to fill in the block. Then, you must use the helper functions
        ## to --- for _no more than `tries` attempts_ --- try to find a
        ## block whose digest (hash) beats the difficulty parameter (has
        ## at least that many leading zeros). After `tries` failed attempts,
        ## the function must return without a block. The `mine` loop will
        ## then run `update_head` and invoke `find_block` again. This makes
        ## sure the node does not waste effort trying to extend the chain
        ## from the head if another node has already done so.
        ##
        ## If successful, returns a tuple of `( block, digest )`,
        ## otherwise, returns `( None, None )`.
        ##
        ## For Part 3, your code must now add a mining transaction. As the
        ## miner, the node designates itself as the recipient to reward
        ## its work in mining the block.

        txn = {
            # this metadata is not usually part of the transaction, but
            # we include to simplify a few tasks for this toy implementation
            'metadata' : {
                'mined' :          True, # a boolean indicating whether it is a mining transaction
                'sender' :         None, # the name (self.port) of the node which created the transaction
                'prev_txn_index' : None, # the index of the preceeding transaction, for easy reference
            },
            'data' : {
                'signature' : 0, # a digital signature certifying that the sender has sent the recipient the coin
                'recipient' : self.verify_key, # the public key of the recipient
                'digest':    0, # the digest (hash) of the preceeding transaction
            }
        }

        txns.append(txn)

        block = {
            'header' : {
                'index'     : index, # the index of the block in the chain
                'parent'    : parent, # the digest (hash) of the parent block
                'nonce'     : self.get_nonce(), # a nonce (number used only once) to vary the hash during mining
                'timestamp' : self.get_timestamp(), # the timestamp of the block
            },
            'transactions' : txns,  # a list of transactions to be included in the block
        }
        
        i = 0
        while i < tries:
            digest = self.hash_block(block)
            if self.leading(digest) >= self.difficulty:
                return ( block, digest )
            else:
                block['header']['nonce'] = self.get_nonce()
            i+=1
        # could very reasonably fail with only 1000 tries and 17 difficulty setting
        return ( None, None )

    def verify_block( self, block, digest ):
        #####
        ## verify_block implements block verification, for use by `update_head`.
        ##
        ## For Part 1, you'll need to implement five checks. For Part 3, you'll add one more.
        ##
        ## Returns a boolean.
        # check: something to do with the timestamp (block is not from the future and previous block is older than this block)
        prev_block = self.blocks.get(block['header']['parent'])
        if block['header']['timestamp'] > time.time() or (prev_block and block['header']['timestamp'] < prev_block['header']['timestamp']):
            return False
        # check: something to do with the hash (the digest is associated with the block)
        if self.hash_block(block) != digest:
            return False
        # check: something else to do with the hash (the digest has the required number of zero bits)
        if self.leading(digest) < DIFFICULTY:
            return False
        # check: something to do with the parent (make sure it's not the genesis block and then check if the parent block exists)
        if prev_block and block['header']['parent'] not in self.blocks.keys():
            return False
        # check: something to do with the parent/index (the block's index is > its parent's index i.e. block is in order. Going to go extra and force the block to have an index exactly 1 greater)
        if prev_block and block['header']['index'] != prev_block['header']['index'] + 1:
            return False
        # (Part 3) check: something to do with the mining transaction (check that mining transaction is the last one)
        txns = block['transactions']
        if len(txns) == 0 or not txns[-1]['metadata']['mined']:
            return False
        return True


    def update_head( self ):
        #####
        ## update_head implements the consensus mechanism. To do this,
        ## it processes blocks received by the network to make sure it is
        ## always on the longest chain
        ##
        ## For Part 1, your code must process the _entirety_ of the queue
        ## `self.pending`.  Each entry is the digest (hash) of a block, and
        ## you can look up the corresponding block object by
        ## `self.blocks[ digest ]`.  For any block which passes
        ## `verify_block`, you must check how long its corresponding chain
        ## is against the length of the current chain (`self.length`).  You
        ## must not trust the `index` parameter provided.  When you find a
        ## new longest chain, you must update `self.head` (the digest of
        ## the head of the chain) and `self.length` accordingly.
        ##
        ## Does not return.
        ##
        ## For Part 3, your code has the additional task of making sure
        ## `self.wallet` contains all and only those coins belonging to
        ## the node on the longest chain. For this assignment you _do not_
        ## need to verify the transactions. Just update `self.wallet`
        ## belonging to the node with all coins currently.
        while True:
            try:
                digest = self.pending.get(False)
            except Empty:
                break
            block = self.blocks[digest]
            if self.verify_block(block, digest):
                # Now check the length of the chain
                chain_len = 1
                curr = block
                # can change back later to no longer use parent reference
                parent = self.blocks.get(curr['header']['parent'])
                chain = [curr]
                while parent is not None:
                    chain_len += 1
                    curr = parent
                    parent = self.blocks.get(curr['header']['parent'])
                    chain.append(curr)
                if chain_len > self.length:
                    self.head = digest
                    self.length = chain_len
                    # Now update the wallet
                    # Not very efficient, but reset the wallet every time
                    self.wallet = []
                    # in order traversal
                    chain.reverse()
                    indices = [int(b['header']['index']) for b in chain]
                    for i in indices:
                        try:
                            curr = chain[i]
                        except IndexError:
                            # was getting strange error before, fixed now
                            print(chain_len)
                            for b in chain: print("{}, ".format(b['header']['index']), end=None)
                            continue
                        for t in curr['transactions']:
                            # if curr is the recipient then add it to the wallet
                            if str(t['data']['recipient']) == self.verify_key:
                                coin = t
                                self.wallet.append(coin)
                            # if curr is the sender then get rid of the coin from wallet
                            elif t['metadata']['sender'] and int(t['metadata']['sender']) == self.port:
                                # remove the previous transaction
                                prev_txn_block = chain[t['metadata']['prev_txn_index']]
                                prev_txn_hash = t['data']['digest']
                                for t in prev_txn_block['transactions']: 
                                    if prev_txn_hash == self.hash_txn(t['data']['recipient'], t['data']['digest'], t['data']['signature']):
                                        self.wallet.remove(t)
                                        break
            self.pending.task_done()

    def gift_coin( self, txns ):
        #####
        ## gift_coin implements coin sending. You must use the following
        ## `txn` object.
        ##
        ## If there is at least one coin in `self.wallet`, you must pick
        ## another node (your choice how, the list of nodes is provided
        ## by `self.peers.keys()`) and create a transaction sending it
        ## to them.
        ##
        ## Whether a transaction is added to it or not, returns `txns`.
        if len(self.wallet) > 0:
            peers_list = list(self.peers.keys())
            i = peers_list.index(self.port)
            dest = self.lookup_key(peers_list[ (i + 1) % len(peers_list) ])
            txn = self.wallet[0] # this is the one we're sending
            
            # find old_txn's blockchain index
            chain = self.get_chain()
            for block in chain:
                try:
                    block['transactions'].index(txn)
                except ValueError:
                    continue
                else:
                    block_index = block['header']['index']
                    break

            # transaction should always exist in chain
            # renamed this to new_txn 
            txn_hash = self.hash_txn(txn['data']['recipient'], txn['data']['digest'], txn['data']['signature'])
            new_txn = {
                # this metadata is not usually part of the transaction, but
                # we include to simplify a few tasks for this toy implementation
                'metadata' : {
                    'mined' :          False, # a boolean indicating whether it is a mining transaction
                    'sender' :         self.port, # the name (self.port) of the node which created the transaction
                    'prev_txn_index' : block_index, # the index of the preceeding transaction, for easy reference
                },
                'data' : {
                    'signature' : self.sign(self.hash_txn_with_recipient(txn_hash, dest)), # a digital signature certifying that the sender has sent the recipient the coin
                    'recipient' : dest, # the public key of the recipient
                    'digest':     txn_hash, # the digest (hash) of the preceeding transaction
                }
            }
            txns.append(new_txn)
        # should use the function hash_txn_with_recipient()
        return txns


    def verify_txn( self, txn ):
        #####
        ## verify_txn implements transaction verification for Part 3
        ## using the helper functions.
        ##
        ## Returns a boolean.
        if txn['metadata']['mined']:
            return True
        try:
            sender_pk = self.lookup_key(txn['metadata']['sender'])
            self.verify(sender_pk, self.hash_txn_with_recipient(txn['data']['digest'], txn['data']['recipient']), txn['data']['signature'])
            return True
        except InvalidSignature:
            return False


    def mine( self ):

        while True:
            self.update_head()
            if not self.head:
                print( "node {} waiting for genesis block".format( self.port ) )

                time.sleep( 5 )
                continue

            if self.length >= STOPPING:

                ## print some statistics
                print( 'node {} - length {} - head {}'.format( self.port, self.length, self.head ) )
                if self.port == 8002:
                    time.sleep( 3 )
                    pp = pprint.PrettyPrinter()
                    pp.pprint( self.blocks )
                

                    self.verify_last_txn()

                return

            txns  = self.gift_coin( [] )
            index = self.blocks[ self.head ][ 'header' ][ 'index' ] + 1
            block, digest = self.find_block( 1000, index, self.head, txns )
            if block:
                self.serialize( block, digest )



#################################################################
# LOW LEVEL THREADING/NETWORKING -- NOT RELEVANT FOR ASSIGNMENT #
#################################################################


def get_handler( bc ):

    class ThreadedTCPRequestHandler( socketserver.BaseRequestHandler ):

        def handle( self ):
            raw = b''
            while True:
                seg = self.request.recv( 4096 )
                raw += seg
                if len( seg ) < 4096:
                    break

            data = str( raw, 'utf-8' )
            bc.deserialize( data )

    return ThreadedTCPRequestHandler


class ThreadedTCPServer( socketserver.ThreadingMixIn, socketserver.TCPServer ):
    pass


def launch( node, peers ):

    bc = Blockchain( node, peers )

    server = ThreadedTCPServer( ( bc.ip, bc.port ), get_handler( bc ) )
    ThreadedTCPServer.allow_reuse_address = True
    with server:
        ip, port = server.server_address

        server_thread = threading.Thread( target = server.serve_forever )
        server_thread.daemon = True
        server_thread.start()

        bc.mine()

        server.shutdown()


if __name__ == '__main__':

    nodes = []
    peers = {}
    for i in range( NNODES ):
        port = 8000 + i
        sk = Ed25519PrivateKey.generate()
        pk = sk.public_key()
        pkb = pk.public_bytes( encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw )
        epk = pkb.hex()

        nodes.append( { 'ip' : '127.0.0.1', 'port' : port, 'sk' : sk, 'pk' : pk, 'epk' : epk } )
        peers[ port ] = { 'ip' : '127.0.0.1', 'port' : port, 'pk' : pk, 'epk' : epk }

    for j in range( NNODES ):
        thread = threading.Thread( target = launch, args = ( nodes[ j ], peers ) )
        thread.start()

    thread.join()
