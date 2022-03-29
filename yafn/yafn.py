import os
import os.path
import sys
import uuid
import time
import zlib
import random
import struct
import socket
import pathlib
import threading
import urllib.request

import zmq
import cbor2

from Crypto.Hash import SHA256, RIPEMD160
from Crypto.Cipher import AES, Salsa20, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA

from . import log

ALPHABET = '286USqFxzKsmMBP9c4TOyECkefQZ7otHAjYh5aN1WiLRprnIGwgulV0dDX'

def encode_uid(uid):
  result = '' 

  n = int.from_bytes(uid, 'big')

  while n >= 58:
    m = n % 58
    n //= 58
    result += ALPHABET[m]

  if n > 0:
    result += ALPHABET[n]

  return result

class Timer(threading.Thread):
  def __init__(self, interval, callback, preflight=0):
    super().__init__()
    self.interval = interval
    self.callback = callback
    self.preflight = preflight
    self.event = threading.Event()

  def run(self):
    if self.preflight:
      time.sleep(self.preflight)

      self.callback()

    while not self.event.wait(self.interval):
      self.callback()

def spawn_thread(target, *args):
  thread = threading.Thread(
    target=target,
    args=args
  )
  thread.daemon = True
  thread.start()

def adler32(data):
  return zlib.adler32(data) & 0xffffffff

def ripemd160(data):
  hash = RIPEMD160.new()
  hash.update(data)

  return hash.digest()

def sha256(data):
  hash = SHA256.new()
  hash.update(data)

  return hash.digest()

def generate_uid(pubkey):
  pubkey = pubkey.public_key()

  n = pubkey.n.to_bytes(128, 'big')
  e = pubkey.e.to_bytes(3, 'big')

  return ripemd160(sha256(n + e))

def RSA_generate_keypair():
  keypair = RSA.generate(1024)
  
  return keypair

def RSA_encrypt(data, key):
  key = key.public_key()
  cipher = PKCS1_OAEP.new(key)

  return cipher.encrypt(data)

def RSA_decrypt(data, key):
  cipher = PKCS1_OAEP.new(key)

  return cipher.decrypt(data)

def AES_encrypt(data, key):
  cipher = AES.new(key, AES.MODE_GCM)
  nonce = cipher.nonce

  data, tag = cipher.encrypt_and_digest(data)
  
  return (data, nonce, tag)

def AES_decrypt(data, key, nonce, tag):
  cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

  data = cipher.decrypt(data)
  
  cipher.verify(tag)

  return data

def RSA_AES_hybrid_encrypt(data, public_key):
  public_key = public_key.public_key()
  cipher = PKCS1_OAEP.new(public_key)

  key = get_random_bytes(32)
  data, nonce, tag = AES_encrypt(data, key)

  key = key + nonce + tag
  key = cipher.encrypt(key)

  return (data, key)

def RSA_AES_hybrid_decrypt(data, key, private_key):
  cipher = PKCS1_OAEP.new(private_key)
  
  key = cipher.decrypt(key)
  if len(key) != 64:
    raise ValueError

  key, nonce, tag = key[:32], key[32:48], key[48:64]

  return AES_decrypt(data, key, nonce, tag)

def salsa20_create_encryptor():
  key = get_random_bytes(32)
  cipher = Salsa20.new(key=key)

  return (cipher.nonce + key, cipher)

def salsa20_create_decryptor(key):
  if len(key) != 40:
    raise ValueError

  cipher = Salsa20.new(key=key[8:], nonce=key[:8])
  
  return cipher

def chunked(data, size):
  return [data[i:i+size] for i in range(0, len(data), size)]

class MessageKind:
  PING      = b'P'
  PONG      = b'O'
  BYE       = b'B'

  QUERY     = b'Q'
  QUERY_HIT = b'H'
  NOTAVAIL  = b'N'

  CRAWL     = b'C'
  MAP       = b'M'

  ANNOUNCE  = b'A'

class Message:
  def __init__(self, kind, uid=None, **fields):
    self.kind = kind
    self.uid = uid if uid else get_random_bytes(16)

    self.__dict__.update(**fields)

    self._timestamp = time.time()

  @property
  def age(self):
    return time.time() - self._timestamp

class Part:
  def __init__(self, data, size, n, checksum):
    self.data = data
    self.size = size
    self.n = n
    self.checksum = checksum

class Piece:
  HEADER      = b'\x80YAFN-PIECE\x00\x00'
  HEADER_SIZE = len(HEADER)
  PIECE_SIZE  = 512 * 1024
  PART_SIZE   = 1024

  def __init__(self, timestamp, hash, parts, parts_count):
    self.timestamp = timestamp
    self.hash = hash
    self.parts = parts
    self.parts_count = parts_count

  def join(self):
    data = b''

    for part in self.parts:
      data += part.data

    return data

  def dump(self, fd):
    fd.write(Piece.HEADER)
    
    fd.write(self.hash)
    fd.write(struct.pack('!Q', int(self.timestamp)))
    fd.write(struct.pack('!H', self.parts_count))

    for order, part in zip(range(self.parts_count), self.parts):
      fd.write(struct.pack('!H', order))
      fd.write(struct.pack('!L', part.checksum))
      fd.write(struct.pack('!H', part.size))

      fd.write(part.data)

  @staticmethod
  def load(fd):
    header = fd.read(Piece.HEADER_SIZE)
    if header != Piece.HEADER:
      raise ValueError

    hash = fd.read(32)
    if len(hash) != 32:
      raise ValueError

    timestamp = fd.read(8)
    timestamp = struct.unpack('!Q', timestamp)[0]

    parts_count = fd.read(2)
    parts_count = struct.unpack('!H', parts_count)[0]
    if parts_count < 1:
      raise ValueError

    actual_hash = SHA256.new()
    parts = []

    for n in range(parts_count):
      order = fd.read(2)
      order = struct.unpack('!H', order)[0]
      if order != n:
        raise ValueError

      checksum = fd.read(4)
      checksum = struct.unpack('!L', checksum)[0]

      size = fd.read(2)
      size = struct.unpack('!H', size)[0]
      if size < 1:
        raise ValueError

      data = fd.read(size)
      if len(data) != size:
        raise ValueError

      if adler32(data) != checksum:
        raise ValueError

      parts.append(Part(
        data,
        size,
        order,
        checksum
      ))

      actual_hash.update(data)

    if len(parts) != parts_count:
      raise ValueError

    if actual_hash.digest() != hash:
      raise ValueError

    return Piece(
      timestamp,
      hash,
      parts,
      parts_count
    )

  @staticmethod
  def create(data):
    parts = chunked(data, Piece.PART_SIZE)

    return Piece(
      time.time(),
      sha256(data),
      [
        Part(
          part,
          len(part),
          n,
          adler32(part)
        ) for n, part in zip(range(len(parts)), parts)
      ],
      len(parts)
    )

class Storage:
  YAFN_DIR = os.path.join(
    pathlib.Path.home(),
    'yafn'
  )

  STORAGE_DIR = os.path.join(
    YAFN_DIR,
    '.storage'
  )

  KEYPAIR_FILE = os.path.join(
    YAFN_DIR,
    'keypair.pem',
  )

  TRACKERS_FILE = os.path.join(
    YAFN_DIR,
    'trackers.txt'
  )

  @staticmethod
  def setup():
    if not os.path.isdir(Storage.YAFN_DIR):
      os.mkdir(Storage.YAFN_DIR)

    if not os.path.isdir(Storage.STORAGE_DIR):
      os.mkdir(Storage.STORAGE_DIR)

    if not os.path.isfile(Storage.TRACKERS_FILE):
      open(Storage.TRACKERS_FILE, 'w').close()
    
  @staticmethod
  def get_keypair():
    if not os.path.isfile(Storage.KEYPAIR_FILE):
      keypair = RSA_generate_keypair()

      with open(Storage.KEYPAIR_FILE, 'wb') as f:
        f.write(keypair.export_key())

      return keypair

    with open(Storage.KEYPAIR_FILE, 'rb') as f:
      keypair = RSA.import_key(f.read())

    return keypair

  @staticmethod
  def get_trackers():
    if not os.path.isfile(Storage.TRACKERS_FILE):
      return []

    with open(Storage.TRACKERS_FILE, 'r') as f:
      lines = f.readlines()
      lines = map(lambda line: line.strip(), lines)
      lines = filter(bool, lines)

      return list(set(lines))

  @staticmethod
  def find_piece(hash):
    path = os.path.join(Storage.STORAGE_DIR, hash.hex())
    if not os.path.isfile(path):
      return None

    with open(path, 'rb+') as f:
      try:
        piece = Piece.load(f)
        if piece.hash != hash:
          os.remove(path)

          return None

        piece.timestamp = time.time()
        piece.dump(f)
        
        return piece
      except:
        return None

  @staticmethod
  def save_piece(piece):
    if type(piece) is not Piece:
      piece = Piece.create(piece)

    path = os.path.join(Storage.STORAGE_DIR, piece.hash.hex())
    
    if os.path.isfile(path):
      return piece
    
    with open(path, 'wb') as f:
      piece.dump(f)

    return piece

  @staticmethod
  def list_pieces(only_hash=True):
    pieces = set()
    files = os.listdir(Storage.STORAGE_DIR)

    for file in files:
      piece = Storage.find_piece(bytes.fromhex(file))
      pieces.add(piece.hash if only_hash else piece)

    return pieces
    
  @staticmethod
  def cleanup():
    pieces = Storage.list_pieces(only_hash=False)
    
    for piece in pieces:
      if time.time() - piece.timestamp > 60*60*24*7:
        try:
          path = os.path.join(Storage.STORAGE_DIR, piece.hash.hex())
          
          os.remove(path)
        except:
          pass

class YAFNError(Exception): pass

class CachedMessage:
  def __init__(self, kind, uid):
    self.kind = kind
    self.uid = uid

    self._timestamp = time.time()

  @property
  def age(self):
    return time.time() - self._timestamp

class Map:
  def __init__(self, uid, submaps):
    self.uid = uid
    self.submaps = submaps
    self.submaps_count = len(submaps)

  def dump(self):
    data = b''

    data += self.uid
    data += struct.pack('!H', self.submaps_count)

    for submap in self.submaps:
      data += submap.dump()

    return data

  def split(self):
    data = self.dump()

    return chunked(data, Piece.PART_SIZE)

  @staticmethod
  def _drain(data):
    if len(data) < 20 + 2:
      raise ValueError

    uid = data[:20]
    submaps_count = struct.unpack('!H', data[20:22])[0]

    data = data[22:]

    submaps = []
    while submaps_count > 0:
      data, submap = Map._drain(data)
      submaps.append(submap)

      submaps_count -= 1

    return data, Map(uid, submaps)

  @staticmethod
  def create(data):
    data, map = Map._drain(data)

    if len(data) > 0:
      raise ValueError

    return map

class Connection:
  def __init__(self, peer, socket, addr, is_inbound=True, reconnect_attempts=0):
    self._peer = peer
    self._socket = socket
    self.addr = addr
    self.is_inbound = is_inbound
    self._reconnect_attempts = reconnect_attempts

    self.uid = None
    self.is_alive = True
    self.near_pieces = set()
    self._near_pieces_purge_timestamp = time.time()
    self._send_lock = threading.Lock()
    self._dont_reconnect = False
    self._timestamp = time.time()
    self._queries_pending = 0
    self._messages_pending = 0
    self._queue = []
    self._cache = []    

    self._remote_pubkey = None    

    self._watchdog = Timer(30 if self.is_inbound else 60, self._watch)
    self._watchdog.start()

    self._announcer = Timer(60*10, self.announce)
    self._announcer.start()

  def _watch(self):
    if not self.is_alive:
      return

    if not self._remote_pubkey:
      self.close()

      return

    attempts = 0
    while True:
      attempts += 1

      if attempts > 3:
        self.close()

        return

      message = Message(MessageKind.PING)

      try:
        self.send(message)
      except:
        continue

      response = self.wait(
        lambda m: m.uid == message.uid and m.kind == MessageKind.PONG,
        timeout=15
      )
      if not response:
        continue

      break

    self._cache = [
      message for message in self._cache if message.age < 60*60
    ]

    self._queue = [
      message for message in self._queue if message.age < 60*5
    ]

    if time.time() - self._near_pieces_purge_timestamp > 60*60*8:
      self.near_pieces = set()

      self._near_pieces_purge_timestamp = time.time()

  def _recvall(self, size):
    buffer = b''

    while len(buffer) != size:
      buffer += self._socket.recv(size - len(buffer))

    return buffer

  def _sendall(self, data):
    self._socket.sendall(data)

  @property
  def age(self):
    return time.time() - self._timestamp

  @property
  def is_ok(self):
    if self.is_alive:
      return True

    try:
      self._peer.connections.remove(self)
    except:
      pass

    return False

  def is_cached(self, message):
    for other_message in self._cache:
      if message.uid == other_message.uid:
        return True

    return False

  def cache(self, message):
    if not self.is_cached(message):
      self._cache.append(CachedMessage(message.kind, message.uid))

  def wait(self, tester, timeout=60):
    start_ts = time.time()

    while time.time() - start_ts < timeout:
      queue = self._queue.copy()
      for message in queue:
        if tester(message):
          try:
            self._queue.remove(message)
          except:
            pass

          return message

      if not self.is_alive:
        return None

      time.sleep(1)

  def close(self):
    if not self.is_alive:
      return

    try:
      self.send(Message(MessageKind.BYE))
    except:
      pass
    finally:
      try:
        self._socket.close()
      except:
        pass

      self._watchdog.event.set()
      self._announcer.event.set()

      try:
        self._peer.connections.remove(self)
      except:
        pass

      self.is_alive = False

      if not self.is_inbound:
        log.warning(f'`{self.addr}` ({self.encoded_uid if self.uid else "n/a"}): Connection lost.')

        if self._dont_reconnect or self._reconnect_attempts >= 5:
          return

        self._reconnect_attempts += 1

        time.sleep(10 * self._reconnect_attempts)

        self._peer.connect_to(self.addr, self._reconnect_attempts)

  def query(self, hash, mid, ttl=7): 
    self._queries_pending += 1

    try:
      self.send(
        Message(
          MessageKind.QUERY,
          uid=mid,
          hash=hash,
          ttl=ttl
        )
      )

      response = self.wait(
        lambda m: m.uid == mid and m.kind in (MessageKind.QUERY_HIT, MessageKind.NOTAVAIL),
        timeout=60*8
      )
      if response and response.kind == MessageKind.QUERY_HIT:
        if response.piece.hash != hash:
          return None

        return response.piece
    except:
      pass
    finally:
      self._queries_pending -= 1

  def crawl(self, mid, ttl=7): 
    try:
      self.send(
        Message(
          MessageKind.CRAWL,
          uid=mid,
          ttl=ttl
        )
      )

      response = self.wait(
        lambda m: m.uid == mid and m.kind in (MessageKind.MAP, MessageKind.NOTAVAIL), 
        timeout=60*10
      )
      if response and response.kind == MessageKind.MAP:
        return response.map
    except:
      pass

  def announce(self):
    if not self.is_alive:
      return

    pieces = Storage.list_pieces()
    if not pieces:
      return

    try:
      self.send(
        Message(
          MessageKind.ANNOUNCE,
          pieces=pieces
        )
      )
    except:
      pass

  def handshake(self):
    self._sendall(b'YAFN HELLO' + self._peer.pubkey)

    data = self._recvall(10 + 162)

    head = data[:10]
    if head != b'YAFN HELLO':
      raise YAFNError
      
    remote_pubkey = RSA.import_key(data[10:]).public_key()
    remote_uid = generate_uid(remote_pubkey)

    if remote_uid == self._peer.uid or remote_uid in [
      conn.uid for conn in self._peer.connections.copy() if conn.is_ok
    ]:
      self._dont_reconnect = True

      raise YAFNError

    random_data = get_random_bytes(16)
    data = RSA_encrypt(random_data, remote_pubkey)

    self._sendall(b'CHECK' + data)

    data = self._recvall(5 + 128)
    
    head = data[:5]
    if head != b'CHECK':
      raise YAFNError

    remote_data = data[5:]
    remote_data = RSA_decrypt(remote_data, self._peer.keypair)

    self._sendall(b'CHECKED' + remote_data)

    data = self._recvall(7 + 16)
    
    head = data[:7]
    if head != b'CHECKED':
      raise YAFNError

    if data[7:] != random_data:
      raise YAFNError

    self._sendall(b'FINISH')

    head = self._recvall(6)
    if head != b'FINISH':
      raise YAFNError

    self._remote_pubkey = remote_pubkey
    self.uid = remote_uid
    self.encoded_uid = encode_uid(self.uid)

    if not self.is_inbound:
      log.info(f'`{self.addr}` ({self.encoded_uid}): Connection successful.')

      self._reconnect_attempts = 0

  def _receive_parts(self, key, parts_count):
    data = b''
    total = 0
    cipher = salsa20_create_decryptor(key)

    try:
      self._socket.settimeout(5)

      while total < parts_count:
        head = self._recvall(6)
        
        checksum = head[:4]
        checksum = struct.unpack('!L', checksum)[0]

        part_size = head[4:6]
        part_size = struct.unpack('!H', part_size)[0]

        part = self._recvall(part_size)
        part = cipher.decrypt(part)
        if adler32(part) != checksum:
          raise YAFNError

        data += part

        total += 1
    finally:
      self._socket.settimeout(None)

    return data

  def receive(self):
    head = self._recvall(4 + 2 + 16 + 128)

    checksum = head[:4]
    size = head[4:6]
    uid = head[6:22]
    key = head[22:150]

    checksum = struct.unpack('!L', checksum)[0]
    size = struct.unpack('!H', size)[0]

    if size > 1024:
      raise YAFNError

    message = self._recvall(size)
    message = RSA_AES_hybrid_decrypt(message, key, self._peer.keypair)

    if adler32(message) != checksum:
      raise YAFNError

    kind = message[:1]
    payload = message[1:]
    payload_size = len(payload)

    fields = {}

    if kind in (
      MessageKind.PING,
      MessageKind.PONG,
      MessageKind.BYE,
      MessageKind.NOTAVAIL
    ):
      if payload_size != 0:
        raise YAFNError
    elif kind == MessageKind.QUERY:
      if payload_size != 32 + 1:
        raise YAFNError

      hash = payload[:32]
      ttl = payload[32]

      if ttl > 7:
        raise YAFNError

      fields['hash'] = hash
      fields['ttl'] = ttl
    elif kind == MessageKind.QUERY_HIT:
      if payload_size != 40 + 2:
        raise YAFNError

      key = payload[:40]
      parts_count = struct.unpack('!H', payload[40:42])[0]

      data = self._receive_parts(key, parts_count)

      fields['piece'] = Piece.create(data)
    elif kind == MessageKind.CRAWL:
      if payload_size != 1:
        raise YAFNError

      ttl = payload[0]

      if ttl > 7:
        raise YAFNError

      fields['ttl'] = ttl
    elif kind == MessageKind.MAP:
      if payload_size != 40 + 2:
        raise YAFNError

      key = payload[:40]
      parts_count = struct.unpack('!H', payload[40:42])[0]

      data = self._receive_parts(key, parts_count)

      fields['map'] = Map.create(data)
    elif kind == MessageKind.ANNOUNCE:
      if payload_size != 40 + 4:
        raise YAFNError

      key = payload[:40]
      parts_count = struct.unpack('!L', payload[40:44])[0]

      data = self._receive_parts(key, parts_count)

      if len(data) < 32 or len(data) % 32 != 0:
        raise YAFNError

      fields['pieces'] = set(chunked(data, 32))
    else:
      raise YAFNError

    return Message(kind, uid, **fields)

  def _send_parts(self, cipher, parts):
    for part in parts:
      checksum = adler32(part)
      data = cipher.encrypt(part)
        
      self._sendall(struct.pack('!L', checksum) + struct.pack('!H', len(data)))
      self._sendall(data)

  def send(self, message):
    head = b''
    payload = message.kind

    if message.kind == MessageKind.QUERY:
      payload += message.hash
      payload += bytes([message.ttl])
    elif message.kind == MessageKind.CRAWL:
      payload += bytes([message.ttl])
    elif message.kind in (
      MessageKind.QUERY_HIT,
      MessageKind.MAP,
      MessageKind.ANNOUNCE
    ):
      key, cipher = salsa20_create_encryptor()

      if message.kind == MessageKind.MAP:
        map_parts = message.map.split()
      elif message.kind == MessageKind.ANNOUNCE:
        splitted_pieces = b''.join(message.pieces)
        splitted_pieces = chunked(splitted_pieces, Piece.PART_SIZE)

      payload += key    

      if message.kind == MessageKind.ANNOUNCE:
        payload += struct.pack('!L', len(splitted_pieces))
      else:
        payload += struct.pack('!H', len(map_parts) if message.kind == MessageKind.MAP else message.piece.parts_count)
   
    checksum = adler32(payload)

    payload, key = RSA_AES_hybrid_encrypt(payload, self._remote_pubkey)

    head += struct.pack('!L', checksum)
    head += struct.pack('!H', len(payload))
    head += message.uid
    head += key

    try:
      self._send_lock.acquire()

      self._sendall(head + payload)

      if message.kind == MessageKind.QUERY_HIT:
        self._send_parts(cipher, [
          part.data for part in message.piece.parts
        ])
      elif message.kind == MessageKind.MAP:
        self._send_parts(cipher, map_parts)
      elif message.kind == MessageKind.ANNOUNCE:
        self._send_parts(cipher, splitted_pieces)
    finally:
      self._send_lock.release()

  def _process(self, message):
    try:
      if message.kind == MessageKind.PING:
        self.send(
          Message(
            MessageKind.PONG,
            uid=message.uid
          )
        )
      elif message.kind == MessageKind.BYE:
        self.close()
      elif message.kind == MessageKind.QUERY:
        if self._queries_pending >= 3 or message.ttl < 1 or self.is_cached(message):
          self.send(
            Message(
              MessageKind.NOTAVAIL,
              uid=message.uid
            )
          )

          return

        self.cache(message)

        piece = self._peer.query(message.hash, message.uid, message.ttl - 1, self)
        if piece:
          self.send(
            Message(
              MessageKind.QUERY_HIT,
              uid=message.uid,
              piece=piece
            )
          )

          return

        self.send(
          Message(
            MessageKind.NOTAVAIL,
            uid=message.uid
          )
        )
      elif message.kind == MessageKind.CRAWL:
        if message.ttl <= 1:
          self.send(
            Message(
              MessageKind.NOTAVAIL,
              uid=message.uid
            )
          )

          return

        if self.is_cached(message):          
          self.send(
            Message(
              MessageKind.MAP,
              uid=message.uid,
              map=self._peer.crawl(None, flat=True)
            )
          )

          return

        self.cache(message)

        map = self._peer.crawl(message.uid, message.ttl - 1, self)
        
        self.send(
          Message(
            MessageKind.MAP,
            uid=message.uid,
            map=map
          )
        )
      elif message.kind == MessageKind.ANNOUNCE:
        self.near_pieces = message.pieces   
    except:
      self.close()

  def listen(self):
    try:
      self.handshake()
    except:
      if not self.is_inbound:
        log.error(f'`{self.addr}` ({self.encoded_uid}): Handshake problem.')

      self.close()

      return

    self._peer.connections.append(self)

    self.announce()

    while self.is_alive:
      try:
        message = self.receive()
      except:
        self.close()

        return

      if message.kind in (
        MessageKind.PING,
        MessageKind.ANNOUNCE
      ):
        if self.is_cached(message):
          continue

        self.cache(message)      
      elif message.kind in (
        MessageKind.PONG,
        MessageKind.QUERY_HIT,
        MessageKind.NOTAVAIL,
        MessageKind.MAP
      ):
        self._queue.append(message)

        continue

      spawn_thread(self._process, message)

class Interface:
  def __init__(self, conn, peer=None):
    self._conn = conn
    self._peer = peer

  def close(self):
    self._conn.close()

  def _contact(self, command, data=b''):
    self._conn.send(command + data)

    response = self._conn.recv()

    return (response[:4], response[4:])

  def save(self, piece):
    response, data = self._contact(b'SAVE', piece)

    if response == b'SAVD':
      return data

  def query(self, hash):
    response, data = self._contact(b'FIND', hash)

    if response == b'QHIT':
      return data

  def crawl(self):
    response, data = self._contact(b'CRWL')

    if response == b'NMAP':
      return Map.create(data)

  def announce(self):
    response, _ = self._contact(b'ANON')

    return response == b'DONE'
    
  def discover(self):
    response, _ = self._contact(b'DISC')

    return response == b'DONE'
    
  def cleanup(self):
    response, _ = self._contact(b'CLNP')

    return response == b'DONE'

  def listen(self):
    while True:
      query = self._conn.recv()

      if len(query) < 4:
        continue

      command = query[:4]
      data = query[4:]

      try:
        if command == b'SAVE':
          if len(data) < 1 or len(data) > Piece.PIECE_SIZE:
            raise YAFNError

          key, cipher = salsa20_create_encryptor()
          checksum = adler32(data)

          data = zlib.compress(data, 9)[2:-4]
          data = cipher.encrypt(data)
          piece = Storage.save_piece(data)

          self._conn.send(b'SAVD' + piece.hash + key + struct.pack('!L', checksum))
        elif command == b'FIND':
          if len(data) != 32 + 40 + 4:
            raise YAFNError

          hash = data[:32]
          key = data[32:72]
          checksum = struct.unpack('!L', data[72:76])[0]

          piece = self._peer.query(hash, uuid.uuid1().bytes)

          if piece:
            data = piece.join()

            cipher = salsa20_create_decryptor(key)
            data = cipher.decrypt(data)
            data = zlib.decompress(data, -15)

            if adler32(data) != checksum:
              raise YAFNError

            self._conn.send(b'QHIT' + data)

            continue

          self._conn.send(b'NOTA')
        elif command == b'CRWL':
          if len(data) != 0:
            raise YAFNError

          map = self._peer.crawl(uuid.uuid1().bytes)

          self._conn.send(b'NMAP' + map.dump())
        elif command == b'ANON':
          if len(data) != 0:
            raise YAFNError

          self._peer.announce()

          self._conn.send(b'DONE')
        elif command == b'DISC':
          if len(data) != 0:
            raise YAFNError

          self._peer.discover()

          self._conn.send(b'DONE')
        elif command == b'CLNP':
          if len(data) != 0:
            raise YAFNError

          Storage.cleanup()

          self._conn.send(b'DONE')
        else:
          raise YAFNError
      except:
        self._conn.send(b'FAIL')

  @staticmethod
  def create(peer):
    context = zmq.Context()
    conn = context.socket(zmq.REP)
    
    while True:
      try:
        conn.bind('tcp://*:49872')
      except:
        log.error('Failed to bind the interface.')

        time.sleep(10)

        continue

      break

    return Interface(conn, peer)

  @staticmethod
  def connect():
    context = zmq.Context()
    conn = context.socket(zmq.REQ)
    conn.connect('tcp://127.0.0.1:49872')

    return Interface(conn)

class Tracker:
  def __init__(self, host):
    self.host = host
    self.disabled_for = 0
    self.disabled = False

  def _request(self, remote_addr=None):
    try:
      request = urllib.request.Request(f'http://{self.host}:49873/track')
      if remote_addr:
        request.add_header('YAFN-Remote-Address', remote_addr)

      with urllib.request.urlopen(request, timeout=30) as resp:
        code = resp.getcode()
        data = resp.read()

        return (code, data)
    except:
      return None

    return None

  def _contact(self, remote_addr=None):
    resp = self._request(remote_addr)

    if not resp or resp[0] != 200:
      return None

    try:
      data = cbor2.loads(resp[1])

      if 'remote_addr' not in data\
      or type(data['remote_addr']) is not str:
        return None

      if 'is_accessible' not in data\
      or type(data['is_accessible']) is not bool:
        return None

      if 'peers' not in data\
      or type(data['peers']) is not list\
      or not all(map(
        lambda peer: type(peer) is dict
                 and 'address' in peer and type(peer['address']) is str
                 and 'uid' in peer and type(peer['uid']) is bytes and len(peer['uid']) == 20
                 and 'latency' in peer and type(peer['latency']) is int and peer['latency'] >= 0
                 and 'last_check' in peer and type(peer['last_check']) is int and peer['last_check'] >= 0,
        data['peers']
      )):
        return None

      return data
    except:
      return None

  def contact(self, remote_addr=None):
    if self.disabled:
      if self.disabled_for > 0:
        self.disabled_for -= 1

        return None
      else:
        self.disabled = False

    data = self._contact(remote_addr)

    if not data:
      self.disabled_for += 1

      if self.disabled_for > 3:
        self.disabled = True

    return data

class Peer:
  def __init__(self):
    self.connections = []
    self.trackers = {}
    self.remote_addr = None
    
    self._discover_lock = threading.Lock()

    Storage.setup()

    self.keypair = Storage.get_keypair()
    self.uid = generate_uid(self.keypair)

    self.pubkey = self.keypair.public_key().export_key('DER')

  def _discover_peers(self):
    trackers = Storage.get_trackers()
    
    for host in self.trackers.copy():
      if host not in trackers:
        self.trackers.pop(host, None)
    
    for host in trackers:
      if host not in self.trackers:
        self.trackers[host] = Tracker(host)
      
    peers = set()
    
    if not self.trackers:
      return peers

    for tracker in self.trackers.values():
      data = tracker.contact(self.remote_addr)

      if data is None:
        if tracker.disabled_for <= 1:
          log.error(f'Tracker `{tracker.host}` contact problem.')

        continue

      if data['is_accessible']:
        if not self.remote_addr:
          self.remote_addr = data['remote_addr']

          log.info(f'Remote address: `{self.remote_addr}`.')

      peers = peers.union({
        peer['address'] for peer in data['peers']
      })

    return peers

  def _serve(self):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    while True:
      try:
        s.bind(('0.0.0.0', 49871))
        s.listen()
      except:
        log.error('Failed to bind the port.')

        time.sleep(15)

        continue

      break
      
    log.info('Ready to accept incoming connections.')

    while True:
      try:
        conn, remote = s.accept()
      except:
        continue

      conn = Connection(
        self,
        conn,
        remote[0]
      )
      spawn_thread(conn.listen)

  def _connect_to(self, host, reconnect_attempts=0):
    log.info(f'`{host}`: Connecting...')

    try:
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      s.connect((host, 49871))
    except:
      log.error(f'`{host}`: Connection problem.')

      if reconnect_attempts < 5:
        time.sleep(10 * max(reconnect_attempts, 1))

        self.connect_to(host, reconnect_attempts + 1)

      return

    conn = Connection(
      self,
      s,
      host,
      False,
      reconnect_attempts
    )
    conn.listen()

  def query(self, hash, mid, ttl=7, came_from=None):
    piece = Storage.find_piece(hash)

    if piece:
      return piece

    if ttl < 1:
      return None

    connections = self.connections.copy()
    inbound_connections = []
    outbound_connections = []

    for conn in connections:
      if came_from and came_from.uid == conn.uid:
        continue

      if not conn.is_ok:
        continue
   
      if conn.is_inbound:
        inbound_connections.append(conn)
      else:
        outbound_connections.append(conn)

    random.shuffle(inbound_connections)
    random.shuffle(outbound_connections)

    if came_from and came_from.is_inbound:
      connections = inbound_connections + outbound_connections
    else:
      connections = outbound_connections + inbound_connections

    for conn in connections:
      if not conn.is_ok:
        continue

      if hash in conn.near_pieces:
        piece = conn.query(hash, mid, ttl)
        if piece:
          return Storage.save_piece(piece)

    for conn in connections:
      if not conn.is_ok:
        continue

      piece = conn.query(hash, mid, ttl)
      if piece:
        return Storage.save_piece(piece)

  def crawl(self, mid, ttl=7, came_from=None, flat=False):
    connections = self.connections.copy()
    submaps = []

    for conn in connections:
      if came_from and came_from.uid == conn.uid:
        continue

      if not conn.is_ok:
        continue

      if flat:
        submaps.append(Map(conn.uid, []))
      else:
        map = conn.crawl(mid, ttl)
        if map:
          submaps.append(map)

    return Map(self.uid, submaps)

  def announce(self):
    connections = self.connections.copy()

    for conn in connections:
      if not conn.is_ok:
        continue

      conn.announce()
      
  def discover(self):
    try:
      self._discover_lock.acquire()
      
      peers = self._discover_peers()
    finally:
      self._discover_lock.release()
    
    addrs = [
      conn.addr for conn in self.connections.copy()
    ]
    peers = [
      addr for addr in peers if addr not in addrs
    ]
    if not peers:
      return

    log.info(f'Discovered {len(peers)} peer{"s" if len(peers) != 1 else ""}.')

    for addr in peers:
      self.connect_to(addr)

  def connect_to(self, addr, reconnect_attempts=0):
    if addr == self.remote_addr:
      return

    for conn in self.connections.copy():
      if conn.addr == addr:
        return

    spawn_thread(self._connect_to, addr, reconnect_attempts)

  def start(self, remote_addr=None):
    log.info('Starting up.')
    log.info(f'Peer UID: {encode_uid(self.uid)}.')

    if remote_addr:
      self.remote_addr = remote_addr

      log.info(f'Remote address: `{self.remote_addr}`.')

    spawn_thread(self._serve)

    Timer(
      60*5,
      self.discover,
      2
    ).start()

    Interface.create(self).listen()
